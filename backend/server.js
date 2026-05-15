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

function getSessionFromRequest(req) {
  const auth = req.headers.authorization || "";
  const bearerToken = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const queryToken = typeof req.query?.token === "string" ? req.query.token : "";
  const token = bearerToken || queryToken;

  return verifySession(token);
}

function requireSession(req, res, next) {
  const session = getSessionFromRequest(req);

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
    body: JSON.stringify({ query, variables })
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
          origin
          destination
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

  if (currentState === "available") return "Available";
  if (currentState === "idle" && idleCodeName) return idleCodeName;

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

  res.json({
    sessionToken: signSession({ sid }),
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


const QUEUE_CONFIG_CACHE_TTL_MS = Number(process.env.QUEUE_CONFIG_CACHE_TTL_MS || 30000);

let queueConfigCache = {
  updatedAt: 0,
  queues: [],
  error: null,
  updating: null
};

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function getQueueNameFromTask(task) {
  return (
    task?.lastQueue?.name ||
    task?.firstQueueName ||
    ""
  );
}

function extractQueueList(payload) {
  if (Array.isArray(payload)) return payload;

  const candidates = [
    payload?.data,
    payload?.items,
    payload?.queues,
    payload?.contactServiceQueues,
    payload?.contactServiceQueue,
    payload?.csqs,
    payload?.content,
    payload?.response
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
  }

  return [];
}

function normalizeQueue(queue) {
  return {
    id: String(queue?.id || queue?.queueId || queue?.csqId || queue?.uuid || ""),
    name: String(
      queue?.name ||
      queue?.queueName ||
      queue?.csqName ||
      queue?.displayName ||
      ""
    ),
    raw: queue
  };
}

function queueTeamMatches(queue, userTeamId) {
  const teamId = String(userTeamId || "");
  if (!teamId) return false;

  const teams = [
    ...asArray(queue?.teams),
    ...asArray(queue?.team),
    ...asArray(queue?.assignedTeams),
    ...asArray(queue?.teamList),
    ...asArray(queue?.teamDetails)
  ];

  if (teams.some(t => String(t?.id || t?.teamId || t?.uuid || t) === teamId)) {
    return true;
  }

  const teamIds = [
    ...asArray(queue?.teamIds),
    ...asArray(queue?.teamIdList),
    ...asArray(queue?.assignedTeamIds),
    ...asArray(queue?.teamId)
  ];

  return teamIds.some(id => String(id) === teamId);
}

async function fetchConfigJson(path) {
  const token = await getValidServiceToken();

  const response = await fetch(`${WEBEX_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GET ${path} failed with HTTP ${response.status}: ${text}`);
  }

  return text ? JSON.parse(text) : {};
}

function getQueueConfigEndpoints() {
  const fromEnv = String(process.env.WXCC_QUEUE_CONFIG_ENDPOINTS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);

  if (fromEnv.length) return fromEnv;

  return [
    `/organization/${WEBEX_ORG_ID}/contact-service-queue`,
    `/organization/${WEBEX_ORG_ID}/contact-service-queues`,
    `/organization/${WEBEX_ORG_ID}/queue`,
    `/organization/${WEBEX_ORG_ID}/queues`
  ];
}

async function fetchAllQueueConfigs() {
  const errors = [];

  for (const endpoint of getQueueConfigEndpoints()) {
    try {
      const data = await fetchConfigJson(endpoint);
      const queueList = extractQueueList(data);

      if (queueList.length) {
        return queueList.map(normalizeQueue).filter(q => q.id || q.name);
      }

      errors.push(`${endpoint}: no queue array found`);
    } catch (err) {
      errors.push(err.message);
    }
  }

  throw new Error(`Could not load WXCC queue configuration. Tried: ${errors.join(" | ")}`);
}

async function getQueueConfig(force = false) {
  const now = Date.now();

  if (
    !force &&
    queueConfigCache.updatedAt &&
    now - queueConfigCache.updatedAt < QUEUE_CONFIG_CACHE_TTL_MS
  ) {
    return queueConfigCache;
  }

  if (queueConfigCache.updating) {
    return queueConfigCache.updating;
  }

  queueConfigCache.updating = fetchAllQueueConfigs()
    .then(queues => {
      queueConfigCache.queues = queues;
      queueConfigCache.updatedAt = Date.now();
      queueConfigCache.error = null;
      return queueConfigCache;
    })
    .catch(err => {
      queueConfigCache.queues = [];
      queueConfigCache.updatedAt = Date.now();
      queueConfigCache.error = err;
      return queueConfigCache;
    })
    .finally(() => {
      queueConfigCache.updating = null;
    });

  return queueConfigCache.updating;
}

async function getAllowedQueuesForTeam(userTeamId) {
  const cache = await getQueueConfig(false);

  const allowed = cache.queues
    .filter(q => queueTeamMatches(q.raw, userTeamId))
    .map(q => q.name)
    .filter(Boolean);

  return Array.from(new Set(allowed));
}

function queueNameAllowed(queueName, allowedQueues) {
  const normalizedQueue = normalizeText(queueName);
  if (!normalizedQueue) return false;
  return allowedQueues.some(q => normalizeText(q) === normalizedQueue);
}

app.get("/api/wallboard", requireSession, async (req, res) => {
  try {
    const userTeamId = req.session?.user?.teamId || "";

    const [allAgents, allTasks, allowedQueues] = await Promise.all([
      getAgentSessions(),
      getTaskDetails(),
      getAllowedQueuesForTeam(userTeamId)
    ]);

    const agents = allAgents
      .filter(a => a.isActive === true)
      .filter(a => a.teamId === userTeamId);

    const telephonyTasks = allTasks
      .filter(t => String(t.channelType).toLowerCase() === "telephony");

    const allowedQueueTasks = telephonyTasks
      .filter(t => queueNameAllowed(getQueueNameFromTask(t), allowedQueues));

    const waitingTasks = allowedQueueTasks
      .filter(t => t?.isActive === true)
      .filter(t => ["new", "parked"].includes(String(t.status).toLowerCase()));

    const connectedTasks = allowedQueueTasks.filter(
      t => String(t.status).toLowerCase() === "connected"
    );

    const avgWaitSeconds =
      allowedQueueTasks.length > 0
        ? Math.round(
            allowedQueueTasks.reduce((sum, t) => sum + Number(t.queueDuration || 0), 0) /
              allowedQueueTasks.length /
              1000
          )
        : 0;

    const avgHandleSeconds =
      allowedQueueTasks.length > 0
        ? Math.round(
            allowedQueueTasks.reduce((sum, t) => sum + Number(t.connectedDuration || 0), 0) /
              allowedQueueTasks.length /
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
      queueSource: "wxcc-config-api",
      entryPointId: ENTRY_POINT_ID,
      teamId: userTeamId,
      generatedAt: new Date().toISOString(),
      allowedQueues,
      queueConfigError: queueConfigCache.error?.message || null,

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

      taskList: connectedTasks.map(task => ({
        id: task.id,
        status: task.status,
        caller: task.origin || "",
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
        caller: task.origin || "",
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

app.get("/api/debug/queues", requireSession, async (req, res) => {
  try {
    const userTeamId = req.session?.user?.teamId || "";
    const cache = await getQueueConfig(true);
    const allowedQueues = await getAllowedQueuesForTeam(userTeamId);

    res.json({
      ok: true,
      teamId: userTeamId,
      allowedQueues,
      queueConfigError: queueConfigCache.error?.message || null,
      queueCount: cache.queues.length,
      queues: cache.queues.map(q => ({
        id: q.id,
        name: q.name,
        matchesCurrentTeam: queueTeamMatches(q.raw, userTeamId),
        rawTeamFields: {
          teams: q.raw?.teams,
          team: q.raw?.team,
          assignedTeams: q.raw?.assignedTeams,
          teamList: q.raw?.teamList,
          teamDetails: q.raw?.teamDetails,
          teamIds: q.raw?.teamIds,
          teamIdList: q.raw?.teamIdList,
          assignedTeamIds: q.raw?.assignedTeamIds,
          teamId: q.raw?.teamId
        }
      }))
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});



function redactForDebug(value, depth = 0) {
  if (depth > 6) return "[MaxDepth]";

  if (Array.isArray(value)) {
    return value.slice(0, 20).map(item => redactForDebug(item, depth + 1));
  }

  if (value && typeof value === "object") {
    const result = {};

    for (const [key, val] of Object.entries(value)) {
      const lowerKey = key.toLowerCase();

      if (
        lowerKey.includes("token") ||
        lowerKey.includes("secret") ||
        lowerKey.includes("password") ||
        lowerKey.includes("authorization")
      ) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactForDebug(val, depth + 1);
      }
    }

    return result;
  }

  return value;
}

function summarizePayload(payload) {
  const isArray = Array.isArray(payload);
  const root = isArray ? payload : (payload && typeof payload === "object" ? payload : {});
  const keys = payload && typeof payload === "object" ? Object.keys(payload) : [];

  const arrays = [];

  if (payload && typeof payload === "object") {
    for (const [key, value] of Object.entries(payload)) {
      if (Array.isArray(value)) {
        arrays.push({
          key,
          length: value.length,
          sample: redactForDebug(value.slice(0, 3))
        });
      }
    }
  }

  return {
    type: isArray ? "array" : typeof payload,
    keys,
    arrayLength: isArray ? payload.length : undefined,
    arrays,
    sample: redactForDebug(isArray ? payload.slice(0, 5) : root)
  };
}

async function fetchConfigRaw(path) {
  const token = await getValidServiceToken();

  const response = await fetch(`${WEBEX_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    path,
    status: response.status,
    ok: response.ok,
    contentType: response.headers.get("content-type") || "",
    text: json ? undefined : text.slice(0, 2000),
    json
  };
}

function getAccessDiscoveryEndpoints(user) {
  const userId = encodeURIComponent(user?.userId || "");
  const email = encodeURIComponent(user?.email || "");
  const configured = String(process.env.WXCC_ACCESS_DISCOVERY_ENDPOINTS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);

  if (configured.length) return configured;

  const candidates = [
    `/organization/${WEBEX_ORG_ID}/user-profile`,
    `/organization/${WEBEX_ORG_ID}/user-profiles`,
    `/organization/${WEBEX_ORG_ID}/access-profile`,
    `/organization/${WEBEX_ORG_ID}/access-profiles`,
    `/organization/${WEBEX_ORG_ID}/resource-collection`,
    `/organization/${WEBEX_ORG_ID}/resource-collections`,
    `/organization/${WEBEX_ORG_ID}/contact-center-user`,
    `/organization/${WEBEX_ORG_ID}/contact-center-users`,
    `/organization/${WEBEX_ORG_ID}/user`,
    `/organization/${WEBEX_ORG_ID}/users`,
    `/organization/${WEBEX_ORG_ID}/queue`,
    `/organization/${WEBEX_ORG_ID}/queues`,
    `/organization/${WEBEX_ORG_ID}/contact-service-queue`,
    `/organization/${WEBEX_ORG_ID}/contact-service-queues`
  ];

  if (userId) {
    candidates.push(
      `/organization/${WEBEX_ORG_ID}/contact-center-user/${userId}`,
      `/organization/${WEBEX_ORG_ID}/contact-center-users/${userId}`,
      `/organization/${WEBEX_ORG_ID}/user/${userId}`,
      `/organization/${WEBEX_ORG_ID}/users/${userId}`,
      `/organization/${WEBEX_ORG_ID}/user-profile/${userId}`,
      `/organization/${WEBEX_ORG_ID}/access-profile/${userId}`
    );
  }

  if (email) {
    candidates.push(
      `/organization/${WEBEX_ORG_ID}/contact-center-user?email=${email}`,
      `/organization/${WEBEX_ORG_ID}/contact-center-users?email=${email}`,
      `/organization/${WEBEX_ORG_ID}/users?email=${email}`
    );
  }

  return candidates;
}

app.get("/api/debug/access-discovery", requireSession, async (req, res) => {
  const user = req.session?.user || {};
  const raw = String(req.query?.raw || "") === "1";
  const endpoints = getAccessDiscoveryEndpoints(user);
  const results = [];

  for (const endpoint of endpoints) {
    try {
      const result = await fetchConfigRaw(endpoint);

      results.push({
        path: result.path,
        status: result.status,
        ok: result.ok,
        contentType: result.contentType,
        ...(result.ok && result.json
          ? { summary: summarizePayload(result.json), raw: raw ? redactForDebug(result.json) : undefined }
          : { errorText: result.text })
      });
    } catch (err) {
      results.push({
        path: endpoint,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    purpose: "Discover WXCC user profile, access profile, resource collection and queue config endpoints",
    user: {
      email: user.email || "",
      userId: user.userId || "",
      teamId: user.teamId || "",
      displayName: user.displayName || ""
    },
    raw,
    endpointCount: results.length,
    results
  });
});

app.get("/api/debug/session", requireSession, (req, res) => {
  res.json({
    ok: true,
    session: {
      role: req.session.role,
      user: req.session.user,
      expiresAt: req.session.expiresAt
    }
  });
});


app.listen(PORT, () => {
  console.log(`Secure widget backend listening on ${PORT}`);
});
