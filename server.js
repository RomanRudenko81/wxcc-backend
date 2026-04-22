import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://romanrudenko81.github.io";
app.use(cors({ origin: FRONTEND_ORIGIN }));

const WEBEX_BASE_URL = process.env.WEBEX_BASE_URL || "https://api.wxcc-eu2.cisco.com";
const WEBEX_ORG_ID = process.env.WEBEX_ORG_ID || "c2e0792b-e4ea-4025-b456-7edc6d1c92cb";
const WEBEX_CLIENT_ID = process.env.WEBEX_CLIENT_ID;
const WEBEX_CLIENT_SECRET = process.env.WEBEX_CLIENT_SECRET;
const WEBEX_SERVICE_REFRESH_TOKEN = process.env.WEBEX_SERVICE_REFRESH_TOKEN;

const ENTRY_POINT_ID = process.env.ENTRY_POINT_ID || "284cd09a-eef4-40a2-82c6-53d08705e3e3";

const ALLOWED_TEAM_IDS = JSON.parse(process.env.ALLOWED_TEAM_IDS || "[]");
const SUPERVISOR_EMAILS = new Set(JSON.parse(process.env.SUPERVISOR_EMAILS || "[]").map(v => String(v).toLowerCase()));
const SUPERVISOR_USER_IDS = new Set(JSON.parse(process.env.SUPERVISOR_USER_IDS || "[]"));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const SESSION_PRUNE_INTERVAL_MS = Number(process.env.SESSION_PRUNE_INTERVAL_MS || 15 * 60 * 1000);

const sessions = new Map();

let tokenStore = {
  accessToken: null,
  expiresAt: 0
};

function pruneExpiredSessions() {
  const now = Date.now();

  for (const [sid, session] of sessions.entries()) {
    if (!session || session.expiresAt < now) {
      sessions.delete(sid);
    }
  }
}

setInterval(pruneExpiredSessions, SESSION_PRUNE_INTERVAL_MS).unref();

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function safeCompare(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);

  if (aBuf.length !== bBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");
  if (!body || !sig) return null;

  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");

  if (!safeCompare(sig, expected)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  if (!payload.sid || !sessions.has(payload.sid)) return null;

  const stored = sessions.get(payload.sid);
  if (!stored || stored.expiresAt < Date.now()) {
    sessions.delete(payload.sid);
    return null;
  }

  return stored;
}

function getRole(user) {
  const email = String(user.email || "").toLowerCase();
  const userId = String(user.userId || "");
  const teamId = String(user.teamId || "");

  if (!ALLOWED_TEAM_IDS.includes(teamId)) return "denied";
  if (SUPERVISOR_EMAILS.has(email) || SUPERVISOR_USER_IDS.has(userId)) return "supervisor";
  return "viewer";
}

async function safeJson(response) {
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${text}`);
  }

  if (!text || text.trim().startsWith("<")) {
    throw new Error("Expected JSON response but received invalid content");
  }

  return JSON.parse(text);
}

async function refreshServiceAccessToken() {
  const response = await fetch("https://webexapis.com/v1/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: WEBEX_CLIENT_ID,
      client_secret: WEBEX_CLIENT_SECRET,
      refresh_token: WEBEX_SERVICE_REFRESH_TOKEN
    })
  });

  const data = await safeJson(response);

  tokenStore.accessToken = data.access_token;
  tokenStore.expiresAt = Date.now() + data.expires_in * 1000;

  return tokenStore.accessToken;
}

async function getValidServiceToken() {
  if (!WEBEX_CLIENT_ID || !WEBEX_CLIENT_SECRET || !WEBEX_SERVICE_REFRESH_TOKEN) {
    throw new Error("Missing Webex service credentials in environment");
  }

  if (!tokenStore.accessToken || Date.now() >= tokenStore.expiresAt - 60000) {
    return refreshServiceAccessToken();
  }

  return tokenStore.accessToken;
}

function requireSession(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const session = verifySession(token);

  if (!session) {
    return res.status(401).json({
      error: "Invalid or expired session",
      code: "SESSION_INVALID",
      action: "Re-bootstrap the frontend session"
    });
  }

  req.session = session;
  next();
}

function requireWriteRole(req, res, next) {
  if (!["supervisor", "admin"].includes(req.session.role)) {
    return res.status(403).json({ error: "Write access requires supervisor role" });
  }

  next();
}

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    entryPointId: ENTRY_POINT_ID,
    activeSessions: sessions.size,
    sessionTtlMs: SESSION_TTL_MS
  });
});

app.post("/api/session/bootstrap", (req, res) => {
  pruneExpiredSessions();

  const user = {
    email: req.body?.email || "",
    userId: req.body?.userId || "",
    teamId: req.body?.teamId || "",
    displayName: req.body?.displayName || req.body?.email || req.body?.userId || "Unknown User"
  };

  const role = getRole(user);

  if (role === "denied") {
    return res.status(403).json({ error: "User is not in an allowed team" });
  }

  const sid = crypto.randomUUID();
  const session = {
    sid,
    user,
    role,
    expiresAt: Date.now() + SESSION_TTL_MS
  };

  sessions.set(sid, session);

  const sessionToken = signSession({ sid });

  res.json({ sessionToken, role, user, expiresAt: session.expiresAt });
});

app.get("/api/entrypoint/:id", requireSession, async (req, res) => {
  try {
    if (req.params.id !== ENTRY_POINT_ID) {
      return res.status(403).json({ error: "Entrypoint is not allowed" });
    }

    const token = await getValidServiceToken();
    const url = `${WEBEX_BASE_URL}/organization/${WEBEX_ORG_ID}/entry-point/${req.params.id}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      }
    });

    const data = await safeJson(response);

    const overrides = Array.isArray(data.flowOverrideSettings) ? data.flowOverrideSettings : [];
    const emergencyCase = overrides.find(o => o.name === "EmergencyCase");
    const emergencyPrompt = overrides.find(o => o.name === "EmergencyPrompt");

    res.json({
      ...data,
      flowOverrideSettings: overrides,
      emergencyCase: emergencyCase?.value === "true",
      emergencyPrompt: emergencyPrompt?.value || "",
      viewerRole: req.session.role
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/entrypoint/:id", requireSession, requireWriteRole, async (req, res) => {
  try {
    if (req.params.id !== ENTRY_POINT_ID) {
      return res.status(403).json({ error: "Entrypoint is not allowed" });
    }

    const token = await getValidServiceToken();
    const url = `${WEBEX_BASE_URL}/organization/${WEBEX_ORG_ID}/entry-point/${req.params.id}`;

    const getRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      }
    });

    const entryPoint = await safeJson(getRes);
    const existingOverrides = Array.isArray(entryPoint.flowOverrideSettings) ? entryPoint.flowOverrideSettings : [];

    const filteredOverrides = existingOverrides.filter(
      item => item?.name !== "EmergencyCase" && item?.name !== "EmergencyPrompt"
    );

    entryPoint.flowOverrideSettings = [
      ...filteredOverrides,
      {
        name: "EmergencyCase",
        type: "BOOLEAN",
        value: req.body?.EmergencyCase ? "true" : "false"
      },
      {
        name: "EmergencyPrompt",
        type: "STRING",
        value: String(req.body?.EmergencyPrompt || "").trim()
      }
    ];

    const putRes = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(entryPoint)
    });

    const result = await safeJson(putRes);

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Secure widget backend listening on port ${PORT}`);
});
