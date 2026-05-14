import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const DEFAULT_ALLOWED_ORIGINS = [
  "https://romanrudenko81.github.io",
  "https://cdn.jsdelivr.net",
  "https://desktop.wxcc-us1.cisco.com",
  "https://desktop.wxcc-eu1.cisco.com",
  "https://desktop.wxcc-eu2.cisco.com"
];

const ENV_ALLOWED_ORIGINS = String(process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

const ALLOWED_CORS_ORIGINS = [...new Set([
  ...DEFAULT_ALLOWED_ORIGINS,
  ...ENV_ALLOWED_ORIGINS
])];

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_CORS_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

app.options("*", cors());

const WEBEX_BASE_URL = process.env.WEBEX_BASE_URL || "https://api.wxcc-eu2.cisco.com";
const WEBEX_ORG_ID = process.env.WEBEX_ORG_ID || "c2e0792b-e4ea-4025-b456-7edc6d1c92cb";
const WEBEX_CLIENT_ID = process.env.WEBEX_CLIENT_ID;
const WEBEX_CLIENT_SECRET = process.env.WEBEX_CLIENT_SECRET;
const WEBEX_SERVICE_REFRESH_TOKEN = process.env.WEBEX_SERVICE_REFRESH_TOKEN;

const ENTRY_POINT_ID = process.env.ENTRY_POINT_ID || "284cd09a-eef4-40a2-82c6-53d08705e3e3";
const WALLBOARD_TEAM_ID = process.env.WALLBOARD_TEAM_ID || "";

const ALLOWED_TEAM_IDS = JSON.parse(process.env.ALLOWED_TEAM_IDS || "[]");
const SUPERVISOR_EMAILS = new Set(
  JSON.parse(process.env.SUPERVISOR_EMAILS || "[]").map(v => String(v).toLowerCase())
);
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

  if (aBuf.length !== bBuf.length) return false;

  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");
  if (!body || !sig) return null;

  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");

  if (!safeCompare(sig, expected)) return null;

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

  const teamRestrictionEnabled = Array.isArray(ALLOWED_TEAM_IDS) && ALLOWED_TEAM_IDS.length > 0;

  if (teamRestrictionEnabled && !ALLOWED_TEAM_IDS.includes(teamId)) return "denied";

  if (SUPERVISOR_EMAILS.has(email) || SUPERVISOR_USER_IDS.has(userId)) {
    return "supervisor";
  }

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

async function postSearchQuery(query, variables = {}) {
  const token = await getValidServiceToken();

  const response = await fetch(`${WEBEX_BASE_URL}/search`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify({ query, variables })
  });

  const text = await response.text();

  return {
    status: response.status,
    text
  };
}

async function getAgentSessions() {
  const now = Date.now();
  const from = now - 24 * 60 * 60 * 1000;
  const to = now;

  const result = await postSearchQuery(`
    query AgentSessionsWallboard($from: Long!, $to: Long!) {
      agentSession(from: $from, to: $to) {
        agentSessions {
          isActive
          agentId
          agentName
          agentSessionId
          userLoginId
          startTime
          endTime
          state
          teamId
          teamName
          siteName
          channelInfo {
            channelType
            currentState
            idleCodeName
            lastActivityTime
          }
        }
      }
    }
  `, { from, to });

  if (result.status < 200 || result.status >= 300) {
    throw new Error(result.text);
  }

  const data = JSON.parse(result.text);
  return data?.data?.agentSession?.agentSessions || [];
}

async function getTaskDetails() {
  const now = Date.now();
  const from = now - 24 * 60 * 60 * 1000;
  const to = now;

  const result = await postSearchQuery(`
    query TaskDetailsWallboard($from: Long!, $to: Long!) {
      taskDetails(from: $from, to: $to) {
        tasks {
          id
          status
          channelType
          createdTime
          endedTime
          direction
          isActive
          isContactHandled
          isContactOffered
          abandonedType
          contactHandleType
          queueDuration
          connectedDuration
          totalDuration
          lastActivityTime
          firstQueueId
          firstQueueName
          lastQueue {
            id
            name
          }
          lastEntryPoint {
            id
            name
          }
          lastTeam {
            id
            name
          }
          lastAgent {
            id
            name
          }
        }
      }
    }
  `, { from, to });

  if (result.status < 200 || result.status >= 300) {
    throw new Error(result.text);
  }

  const data = JSON.parse(result.text);
  return data?.data?.taskDetails?.tasks || [];
}

function getPrimaryChannelInfo(agent) {
  const channels = Array.isArray(agent.channelInfo) ? agent.channelInfo : [];

  const telephony = channels.find(channel =>
    String(channel.channelType || "").toLowerCase() === "telephony"
  );

  return telephony || channels[0] || null;
}

function getAgentDisplayState(agent) {
  const channel = getPrimaryChannelInfo(agent);

  const currentState = String(channel?.currentState || "")
    .trim()
    .toLowerCase();

  const idleCodeName = String(channel?.idleCodeName || "").trim();

  if (currentState === "available") {
    return "Available";
  }

  if (currentState === "idle" && idleCodeName) {
    return idleCodeName;
  }

  if (currentState) {
    return currentState.charAt(0).toUpperCase() + currentState.slice(1);
  }

  return agent.state || "";
}

function getAgentStateSinceSeconds(agent) {
  const channel = getPrimaryChannelInfo(agent);
  const lastActivityTime = Number(channel?.lastActivityTime || 0);

  if (lastActivityTime > 0) {
    return Math.max(0, Math.floor((Date.now() - lastActivityTime) / 1000));
  }

  if (agent.startTime) {
    return Math.max(0, Math.floor((Date.now() - Number(agent.startTime)) / 1000));
  }

  return null;
}

function isAvailableState(state) {
  return String(state || "").trim().toLowerCase() === "available";
}

function buildAgentWallboard(agentSessions) {
  const activeSessions = agentSessions
    .filter(agent => agent?.isActive === true)
    .filter(agent => !WALLBOARD_TEAM_ID || agent.teamId === WALLBOARD_TEAM_ID);

  const uniqueByAgent = new Map();

  activeSessions.forEach(agent => {
    const key = agent.agentId || agent.userLoginId || agent.agentSessionId;
    const existing = uniqueByAgent.get(key);

    if (!existing || Number(agent.startTime || 0) > Number(existing.startTime || 0)) {
      uniqueByAgent.set(key, agent);
    }
  });

  const activeAgents = [...uniqueByAgent.values()];

  return {
    loggedIn: activeAgents.length,
    available: activeAgents.filter(agent =>
      isAvailableState(getAgentDisplayState(agent))
    ).length,
    agentList: activeAgents
      .sort((a, b) => String(a.agentName || "").localeCompare(String(b.agentName || "")))
      .map(agent => {
        const channel = getPrimaryChannelInfo(agent);
        const displayState = getAgentDisplayState(agent);

        return {
          name: agent.agentName || "",
          login: agent.userLoginId || "",
          state: displayState,
          sessionState: agent.state || "",
          channelType: channel?.channelType || "",
          currentState: channel?.currentState || "",
          idleCodeName: channel?.idleCodeName || "",
          teamId: agent.teamId || "",
          team: agent.teamName || "",
          site: agent.siteName || "",
          startTime: agent.startTime || null,
          lastActivityTime: channel?.lastActivityTime || null,
          activeSinceSeconds: getAgentStateSinceSeconds(agent)
        };
      })
  };
}

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    entryPointId: ENTRY_POINT_ID,
    activeSessions: sessions.size,
    sessionTtlMs: SESSION_TTL_MS,
    teamRestrictionEnabled: Array.isArray(ALLOWED_TEAM_IDS) && ALLOWED_TEAM_IDS.length > 0,
    allowedTeamIds: ALLOWED_TEAM_IDS,
    corsOrigins: ALLOWED_CORS_ORIGINS
  });
});

app.get("/api/wallboard", async (req, res) => {
  try {
    const agentSessions = await getAgentSessions();
    const agentWallboard = buildAgentWallboard(agentSessions);

    res.json({
      ok: true,
      source: "webex-search-api",
      entryPointId: ENTRY_POINT_ID,
      teamFilter: WALLBOARD_TEAM_ID || null,
      generatedAt: new Date().toISOString(),
      queue: {
        callsInQueue: 0,
        longestWaitingSeconds: 0,
        avgWaitSeconds: 0,
        avgHandleSeconds: 0
      },
      agents: {
        loggedIn: agentWallboard.loggedIn,
        available: agentWallboard.available
      },
      agentList: agentWallboard.agentList
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message,
      generatedAt: new Date().toISOString()
    });
  }
});

app.get("/api/wallboard/test-search", async (req, res) => {
  try {
    const result = await postSearchQuery("{ __typename }");
    res.status(result.status).send(result.text);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/wallboard/test-agents", async (req, res) => {
  try {
    const agentSessions = await getAgentSessions();

    res.json({
      count: agentSessions.length,
      agentSessions
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/wallboard/test-tasks", async (req, res) => {
  try {
    const tasks = await getTaskDetails();

    const activeTelephonyTasks = tasks.filter(task =>
      task?.isActive === true &&
      String(task?.channelType || "").toLowerCase() === "telephony"
    );

    res.json({
      count: tasks.length,
      activeTelephonyCount: activeTelephonyTasks.length,
      generatedAt: new Date().toISOString(),
      activeTelephonyTasks,
      tasks: tasks.slice(0, 50)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/wallboard/schema-type/:typeName", async (req, res) => {
  try {
    const allowedTypes = new Set([
      "TaskList",
      "TaskDetailsList",
      "AgentSessions",
      "TaskLegDetailsList",
      "Task",
      "TaskDetails",
      "AgentSession",
      "TaskLegDetails",
      "AgentChannelInfo",
      "Queue",
      "QueueStats",
      "TaskQueue"
    ]);

    const typeName = String(req.params.typeName || "").trim();

    if (!allowedTypes.has(typeName)) {
      return res.status(400).json({
        error: "Type is not allowed for schema inspection",
        allowedTypes: [...allowedTypes]
      });
    }

    const result = await postSearchQuery(`
      query TypeInspection($typeName: String!) {
        __type(name: $typeName) {
          name
          kind
          fields {
            name
            description
            type {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    `, { typeName });

    res.status(result.status).send(result.text);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  const teamRestrictionEnabled = Array.isArray(ALLOWED_TEAM_IDS) && ALLOWED_TEAM_IDS.length > 0;

  if (role === "denied") {
    return res.status(403).json({
      error: "User is not in an allowed team",
      debug: {
        receivedEmail: user.email,
        receivedUserId: user.userId,
        receivedTeamId: user.teamId,
        allowedTeamIds: ALLOWED_TEAM_IDS,
        teamRestrictionEnabled
      }
    });
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

  res.json({
    sessionToken,
    role,
    user,
    expiresAt: session.expiresAt,
    debug: {
      receivedEmail: user.email,
      receivedUserId: user.userId,
      receivedTeamId: user.teamId,
      allowedTeamIds: ALLOWED_TEAM_IDS,
      teamRestrictionEnabled
    }
  });
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

    res.json({
      ...data,
      flowOverrideSettings: overrides,
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
    const existingOverrides = Array.isArray(entryPoint.flowOverrideSettings)
      ? entryPoint.flowOverrideSettings
      : [];

    const managedNames = new Set([
      "Priority_Queue",
      "EmergencyCase",
      "HolidayPrompt",
      "Global_VoiceName",
      "EmergencyPrompt",
      "Global_Language",
      "Moh_Sales_Queue"
    ]);

    const filteredOverrides = existingOverrides.filter(
      item => !managedNames.has(item?.name)
    );

    entryPoint.flowOverrideSettings = [
      ...filteredOverrides,
      {
        name: "Priority_Queue",
        type: "INTEGER",
        value: String(Number(req.body?.Priority_Queue || 1))
      },
      {
        name: "EmergencyCase",
        type: "BOOLEAN",
        value: req.body?.EmergencyCase ? "true" : "false"
      },
      {
        name: "HolidayPrompt",
        type: "STRING",
        value: String(req.body?.HolidayPrompt || "").trim()
      },
      {
        name: "Global_VoiceName",
        type: "STRING",
        value: String(req.body?.Global_VoiceName || "").trim()
      },
      {
        name: "EmergencyPrompt",
        type: "STRING",
        value: String(req.body?.EmergencyPrompt || "").trim()
      },
      {
        name: "Global_Language",
        type: "STRING",
        value: String(req.body?.Global_Language || "").trim()
      },
      {
        name: "Moh_Sales_Queue",
        type: "STRING",
        value: String(req.body?.Moh_Sales_Queue || "").trim()
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

app.use((err, req, res, next) => {
  if (err && String(err.message || "").startsWith("CORS blocked")) {
    return res.status(403).json({
      error: err.message,
      allowedOrigins: ALLOWED_CORS_ORIGINS
    });
  }

  return next(err);
});

app.listen(PORT, () => {
  console.log(`Secure widget backend listening on port ${PORT}`);
});
