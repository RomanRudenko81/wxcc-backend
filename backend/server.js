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

    if (ALLOWED_CORS_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

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
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 28800000);

const ALLOWED_TEAM_IDS = JSON.parse(process.env.ALLOWED_TEAM_IDS || "[]");

const SUPERVISOR_EMAILS = new Set(
  JSON.parse(process.env.SUPERVISOR_EMAILS || "[]").map(v => String(v).toLowerCase())
);

const SUPERVISOR_USER_IDS = new Set(
  JSON.parse(process.env.SUPERVISOR_USER_IDS || "[]")
);

const sessions = new Map();

let tokenStore = {
  accessToken: null,
  expiresAt: 0
};

function safeCompare(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);

  if (aBuf.length !== bBuf.length) return false;

  return crypto.timingSafeEqual(aBuf, bBuf);
}

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

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

function requireSession(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  const session = verifySession(token);

  if (!session) {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }

  req.session = session;
  next();
}

function requireWriteRole(req, res, next) {
  if (!["supervisor", "admin"].includes(req.session.role)) {
    return res.status(403).json({
      error: "Write access denied"
    });
  }

  next();
}

function getRole(user) {
  const email = String(user.email || "").toLowerCase();
  const userId = String(user.userId || "");
  const teamId = String(user.teamId || "");

  if (ALLOWED_TEAM_IDS.length && !ALLOWED_TEAM_IDS.includes(teamId)) {
    return "denied";
  }

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
  if (!tokenStore.accessToken || Date.now() >= tokenStore.expiresAt - 60000) {
    return refreshServiceAccessToken();
  }

  return tokenStore.accessToken;
}

async function getEntryPoint(id) {
  const token = await getValidServiceToken();

  const response = await fetch(
    `${WEBEX_BASE_URL}/organization/${WEBEX_ORG_ID}/entry-point/${id}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      }
    }
  );

  return safeJson(response);
}

async function updateEntryPoint(id, payload) {
  const token = await getValidServiceToken();

  const response = await fetch(
    `${WEBEX_BASE_URL}/organization/${WEBEX_ORG_ID}/entry-point/${id}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    }
  );

  return safeJson(response);
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
    body: JSON.stringify({
      query,
      variables
    })
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(text);
  }

  return JSON.parse(text);
}

async function getAgentSessions() {
  const now = Date.now();

  const result = await postSearchQuery(
    `
    query AgentSessionsWallboard($from: Long!, $to: Long!) {
      agentSession(from: $from, to: $to) {
        agentSessions {
          isActive
          agentId
          agentName
          agentSessionId
          userLoginId
          startTime
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
    `,
    {
      from: now - 86400000,
      to: now
    }
  );

  return result?.data?.agentSession?.agentSessions || [];
}

async function getTaskDetails() {
  const now = Date.now();

  const result = await postSearchQuery(
    `
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
    `,
    {
      from: now - 86400000,
      to: now
    }
  );

  return result?.data?.taskDetails?.tasks || [];
}

function getPrimaryChannelInfo(agent) {
  const channels = Array.isArray(agent.channelInfo) ? agent.channelInfo : [];

  return (
    channels.find(c => String(c.channelType).toLowerCase() === "telephony") ||
    channels[0] ||
    null
  );
}

function getDisplayState(agent) {
  const channel = getPrimaryChannelInfo(agent);

  const currentState = String(channel?.currentState || "").toLowerCase();
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

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    entryPointId: ENTRY_POINT_ID,
    activeSessions: sessions.size,
    sessionTtlMs: SESSION_TTL_MS,
    corsOrigins: ALLOWED_CORS_ORIGINS
  });
});

app.post("/api/session/bootstrap", (req, res) => {
  const user = {
    email: req.body?.email || "",
    userId: req.body?.userId || "",
    teamId: req.body?.teamId || "",
    displayName: req.body?.displayName || req.body?.email || "Unknown"
  };

  const role = getRole(user);

  if (role === "denied") {
    return res.status(403).json({
      error: "User is not in allowed team"
    });
  }

  const sid = crypto.randomUUID();

  const session = {
    sid,
    role,
    user,
    expiresAt: Date.now() + SESSION_TTL_MS
  };

  sessions.set(sid, session);

  const sessionToken = signSession({ sid });

  res.json({
    sessionToken,
    role,
    user,
    expiresAt: session.expiresAt
  });
});

app.get("/api/entrypoint/:id", requireSession, async (req, res) => {
  try {
    const data = await getEntryPoint(req.params.id);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.put("/api/entrypoint/:id", requireSession, requireWriteRole, async (req, res) => {
  try {
    const existing = await getEntryPoint(req.params.id);

    existing.flowOverrideSettings = req.body.flowOverrideSettings || [];

    const updated = await updateEntryPoint(req.params.id, existing);

    res.json(updated);
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.get("/api/wallboard", requireSession, async (req, res) => {
  try {
    const userTeamId = req.session?.user?.teamId || "";

    const [allAgents, allTasks] = await Promise.all([
      getAgentSessions(),
      getTaskDetails()
    ]);

    const agents = allAgents
      .filter(a => a.isActive === true)
      .filter(a => a.teamId === userTeamId);

    const teamTasks = allTasks
      .filter(t => String(t.channelType).toLowerCase() === "telephony")
      .filter(t => t?.lastTeam?.id === userTeamId);

    const waitingTasks = allTasks
      .filter(t => String(t.channelType).toLowerCase() === "telephony")
      .filter(t => t?.isActive === true)
      .filter(t => ["new", "parked"].includes(String(t.status).toLowerCase()))
      .filter(t => t?.lastEntryPoint?.id === ENTRY_POINT_ID);

    const connectedTasks = teamTasks.filter(
      t => String(t.status).toLowerCase() === "connected"
    );

    const kpiTasks = [...teamTasks];

    const avgWaitSeconds =
      kpiTasks.length > 0
        ? Math.round(
            kpiTasks.reduce(
              (sum, t) => sum + Number(t.queueDuration || 0),
              0
            ) /
              kpiTasks.length /
              1000
          )
        : 0;

    const avgHandleSeconds =
      kpiTasks.length > 0
        ? Math.round(
            kpiTasks.reduce(
              (sum, t) => sum + Number(t.connectedDuration || 0),
              0
            ) /
              kpiTasks.length /
              1000
          )
        : 0;

    const longestWaitingSeconds =
      waitingTasks.length > 0
        ? Math.max(
            ...waitingTasks.map(t =>
              Math.floor((Date.now() - Number(t.createdTime || 0)) / 1000)
            )
          )
        : 0;

    const availableAgents = agents.filter(a =>
      String(getDisplayState(a)).toLowerCase() === "available"
    );

    res.json({
      ok: true,
      source: "webex-search-api",
      entryPointId: ENTRY_POINT_ID,
      teamId: userTeamId,
      generatedAt: new Date().toISOString(),

      queue: {
        callsInQueue: waitingTasks.length,
        activeCalls: connectedTasks.length,
        longestWaitingSeconds,
        avgWaitSeconds,
        avgHandleSeconds
      },

      agents: {
        loggedIn: agents.length,
        available: availableAgents.length
      },

      agentList: agents.map(agent => {
        const channel = getPrimaryChannelInfo(agent);

        return {
          name: agent.agentName || "",
          login: agent.userLoginId || "",
          state: getDisplayState(agent),
          currentState: channel?.currentState || "",
          idleCodeName: channel?.idleCodeName || "",
          teamId: agent.teamId || "",
          team: agent.teamName || "",
          site: agent.siteName || "",
          startTime: agent.startTime || null,
          lastActivityTime: channel?.lastActivityTime || null
        };
      }),

      taskList: teamTasks.map(task => ({
        id: task.id,
        status: task.status,
        queue: task?.lastQueue?.name || "",
        firstQueue: task?.firstQueueName || "",
        entryPoint: task?.lastEntryPoint?.name || "",
        agent: task?.lastAgent?.name || "",
        queueDuration: task.queueDuration || 0,
        connectedDuration: task.connectedDuration || 0
      })),

      waitingTaskList: waitingTasks.map(task => ({
        id: task.id,
        status: task.status,
        queue: task?.lastQueue?.name || "",
        firstQueue: task?.firstQueueName || "",
        entryPoint: task?.lastEntryPoint?.name || "",
        createdTime: task.createdTime || null,
        waitingSeconds: task.createdTime
          ? Math.floor((Date.now() - Number(task.createdTime)) / 1000)
          : 0
      }))
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

app.get("/api/wallboard/test-tasks", async (req, res) => {
  try {
    const tasks = await getTaskDetails();

    const telephonyTasks = tasks.filter(
      t => String(t.channelType || "").toLowerCase() === "telephony"
    );

    const activeTelephonyTasks = telephonyTasks.filter(t => t?.isActive === true);

    const possibleWaitingTasks = activeTelephonyTasks.filter(t =>
      ["new", "parked", "connected"].includes(String(t.status || "").toLowerCase())
    );

    res.json({
      count: tasks.length,
      telephonyCount: telephonyTasks.length,
      activeTelephonyCount: activeTelephonyTasks.length,
      possibleWaitingOrActiveCount: possibleWaitingTasks.length,
      generatedAt: new Date().toISOString(),
      activeTelephonyTasks,
      possibleWaitingTasks,
      tasks: tasks.slice(0, 50)
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Secure widget backend listening on ${PORT}`);
});
