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
const BUILD_ID = "wxcc-focus-resume-refresh-fix-2026-05-19-v21";

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

  const taskBaseFields = `
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
          lastQueue { id name }
          lastEntryPoint { id name }
          lastTeam { id name }
          lastAgent { id name }
  `;

  const wrapupVariants = [
    { name: "wrapUpReason", fields: "wrapUpReason" },
    { name: "wrapupReason", fields: "wrapupReason" },
    { name: "wrapUpCodeName", fields: "wrapUpCodeName" },
    { name: "wrapupCodeName", fields: "wrapupCodeName" },
    { name: "wrapUpCode", fields: "wrapUpCode" },
    { name: "wrapupCode", fields: "wrapupCode" },
    { name: "wrapUpReasonName", fields: "wrapUpReasonName" },
    { name: "wrapupReasonName", fields: "wrapupReasonName" },
    { name: "wrapUpData", fields: "wrapUpData { id name }" },
    { name: "wrapupData", fields: "wrapupData { id name }" },
    { name: "wrapUp", fields: "wrapUp { id name }" },
    { name: "wrapup", fields: "wrapup { id name }" },
    { name: "base", fields: "" }
  ];

  const variables = { from: now - 86400000, to: now };

  for (const variant of wrapupVariants) {
    const query = `
      query TaskDetailsWallboard($from: Long!, $to: Long!) {
        taskDetails(from: $from, to: $to) {
          tasks {
            ${taskBaseFields}
            ${variant.fields}
          }
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, variables);
      const tasks = result?.data?.taskDetails?.tasks || [];
      lastTaskDetailsQueryVariant = variant.name;
      return tasks;
    } catch (err) {
      console.warn(`TaskDetails query variant ${variant.name} failed:`, err.message);
    }
  }

  lastTaskDetailsQueryVariant = "failed";
  return [];
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



const ACCESS_CONFIG_CACHE_TTL_MS = Number(process.env.ACCESS_CONFIG_CACHE_TTL_MS || 30000);

let accessConfigCache = {
  updatedAt: 0,
  users: [],
  userProfiles: [],
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

function extractArray(payload, keys = []) {
  if (Array.isArray(payload)) return payload;

  for (const key of keys) {
    if (Array.isArray(payload?.[key])) return payload[key];
  }

  const defaultKeys = [
    "data",
    "items",
    "content",
    "response",
    "users",
    "userProfiles",
    "profiles",
    "queues",
    "contactServiceQueues",
    "contactServiceQueue"
  ];

  for (const key of defaultKeys) {
    if (Array.isArray(payload?.[key])) return payload[key];
  }

  return [];
}

function getQueueNameFromTask(task) {
  return (
    task?.lastQueue?.name ||
    task?.firstQueueName ||
    ""
  );
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
    channelType: String(queue?.channelType || ""),
    active: queue?.active !== false,
    raw: queue
  };
}

function isVoiceQueue(queue) {
  const channelType = normalizeText(queue?.channelType || queue?.raw?.channelType || "");

  return (
    channelType === "telephony" ||
    channelType === "voice"
  );
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

async function fetchAllAccessConfig() {
  const [usersPayload, profilesPayload, queuesPayload] = await Promise.all([
    fetchConfigJson(`/organization/${WEBEX_ORG_ID}/user`),
    fetchConfigJson(`/organization/${WEBEX_ORG_ID}/user-profile`),
    fetchConfigJson(`/organization/${WEBEX_ORG_ID}/contact-service-queue`)
  ]);

  const users = extractArray(usersPayload, ["users"]).filter(Boolean);
  const userProfiles = extractArray(profilesPayload, ["userProfiles", "profiles"]).filter(Boolean);
  const queues = extractArray(queuesPayload, ["contactServiceQueues", "queues", "contactServiceQueue"])
    .map(normalizeQueue)
    .filter(q => q.id || q.name);

  return {
    users,
    userProfiles,
    queues
  };
}

async function getAccessConfig(force = false) {
  const now = Date.now();

  if (
    !force &&
    accessConfigCache.updatedAt &&
    now - accessConfigCache.updatedAt < ACCESS_CONFIG_CACHE_TTL_MS
  ) {
    return accessConfigCache;
  }

  if (accessConfigCache.updating) {
    return accessConfigCache.updating;
  }

  accessConfigCache.updating = fetchAllAccessConfig()
    .then(data => {
      accessConfigCache.users = data.users;
      accessConfigCache.userProfiles = data.userProfiles;
      accessConfigCache.queues = data.queues;
      accessConfigCache.updatedAt = Date.now();
      accessConfigCache.error = null;
      return accessConfigCache;
    })
    .catch(err => {
      accessConfigCache.error = err;
      accessConfigCache.updatedAt = Date.now();
      return accessConfigCache;
    })
    .finally(() => {
      accessConfigCache.updating = null;
    });

  return accessConfigCache.updating;
}

function findCurrentContactCenterUser(users, sessionUser) {
  const userId = String(sessionUser?.userId || "");
  const email = normalizeText(sessionUser?.email || "");

  return users.find(user =>
    String(user?.ciUserId || "") === userId ||
    String(user?.id || "") === userId ||
    (email && normalizeText(user?.email || "") === email)
  ) || null;
}

function findUserProfile(userProfiles, profileId) {
  const id = String(profileId || "");
  return userProfiles.find(profile => String(profile?.id || "") === id) || null;
}

function collectQueueRefs(value, refs = []) {
  if (!value) return refs;

  if (Array.isArray(value)) {
    value.forEach(item => collectQueueRefs(item, refs));
    return refs;
  }

  if (typeof value !== "object") return refs;

  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase();

    if (
      normalizedKey === "queues" ||
      normalizedKey === "queue" ||
      normalizedKey === "queueids" ||
      normalizedKey === "queueidlist" ||
      normalizedKey === "selectedqueues" ||
      normalizedKey === "selectedqueueids"
    ) {
      const items = Array.isArray(child) ? child : [child];

      items.forEach(item => {
        if (!item) return;

        if (typeof item === "string") {
          refs.push({ id: item, name: item });
          return;
        }

        if (typeof item === "object") {
          refs.push({
            id: String(item.id || item.queueId || item.csqId || item.uuid || ""),
            name: String(item.name || item.queueName || item.csqName || item.displayName || "")
          });
        }
      });
    }

    if (typeof child === "object") {
      collectQueueRefs(child, refs);
    }
  }

  return refs;
}

function resolveQueueRefsToNames(queueRefs, queues) {
  const names = new Set();

  queueRefs.forEach(ref => {
    const id = String(ref.id || "");
    const name = String(ref.name || "");

    const match = queues.find(queue =>
      (id && queue.id === id) ||
      (name && normalizeText(queue.name) === normalizeText(name))
    );

    if (match?.name) {
      names.add(match.name);
    } else if (name) {
      names.add(name);
    }
  });

  return [...names];
}

function getAllTelephonyQueueNames(queues) {
  return queues
    .filter(q => q.active)
    .filter(isVoiceQueue)
    .map(q => q.name)
    .filter(Boolean);
}

async function getAllowedQueuesForSession(session) {
  const config = await getAccessConfig(false);

  if (config.error) {
    return {
      allowedQueues: [],
      source: "user-profile",
      error: config.error.message,
      user: null,
      profile: null
    };
  }

  const currentUser = findCurrentContactCenterUser(config.users, session?.user || {});
  const profile = findUserProfile(config.userProfiles, currentUser?.userProfileId);

  if (!currentUser) {
    return {
      allowedQueues: [],
      source: "user-profile",
      error: `No contact center user found for session userId ${session?.user?.userId || ""}`,
      user: null,
      profile: null
    };
  }

  if (!profile) {
    return {
      allowedQueues: [],
      source: "user-profile",
      error: `No user profile found for profileId ${currentUser.userProfileId || ""}`,
      user: currentUser,
      profile: null
    };
  }

  const accessAllQueues = String(profile.accessAllQueues || "").toUpperCase();

  if (accessAllQueues === "ALL") {
    return {
      allowedQueues: getAllTelephonyQueueNames(config.queues),
      source: "user-profile:all-queues",
      error: null,
      user: currentUser,
      profile
    };
  }

  const queueRefs = collectQueueRefs(profile);
  const profileQueueNames = resolveQueueRefsToNames(queueRefs, config.queues);
  const voiceQueueNames = new Set(getAllTelephonyQueueNames(config.queues));
  const allowedQueues = profileQueueNames.filter(name => voiceQueueNames.has(name));

  return {
    allowedQueues,
    source: "user-profile:selected-voice-queues",
    error: allowedQueues.length ? null : "User profile contains no readable selected voice queue references",
    user: currentUser,
    profile
  };
}

function queueNameAllowed(queueName, allowedQueues) {
  const normalizedQueue = normalizeText(queueName);
  if (!normalizedQueue) return false;

  return allowedQueues.some(q => normalizeText(q) === normalizedQueue);
}


const WALLBOARD_DATA_CACHE_TTL_MS = Number(process.env.WALLBOARD_DATA_CACHE_TTL_MS || 5000);
const WALLBOARD_FALLBACK_POLLING_ENABLED =
  String(process.env.WALLBOARD_FALLBACK_POLLING_ENABLED || "false").toLowerCase() === "true";
const SSE_HEARTBEAT_MS = Number(process.env.SSE_HEARTBEAT_MS || 25000);
const WXCC_EVENT_WEBHOOK_SECRET = process.env.WXCC_EVENT_WEBHOOK_SECRET || "";
const EVENT_REFRESH_DEBOUNCE_MS = Number(process.env.EVENT_REFRESH_DEBOUNCE_MS || 1200);
const EVENT_REFRESH_RETRY_DELAYS_MS = String(
  process.env.EVENT_REFRESH_RETRY_DELAYS_MS || "1000,3000,7000,15000"
)
  .split(",")
  .map(v => Number(v.trim()))
  .filter(v => Number.isFinite(v) && v >= 0);

const WXCC_SUBSCRIPTION_TARGET_URL =
  process.env.WXCC_SUBSCRIPTION_TARGET_URL ||
  "https://wxcc-backend.onrender.com/api/wxcc/events";

const WXCC_SUBSCRIPTION_ENDPOINT =
  process.env.WXCC_SUBSCRIPTION_ENDPOINT ||
  "/v1/subscriptions";

const WXCC_SUBSCRIPTION_EVENTS = String(
  process.env.WXCC_SUBSCRIPTION_EVENTS || ""
)
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

const WXCC_EVENT_TYPES_ENDPOINTS = String(
  process.env.WXCC_EVENT_TYPES_ENDPOINTS ||
  "/v1/event-types,/v1/eventTypes,/v1/events/types,/v1/subscriptions/event-types,/v1/subscriptions/eventTypes"
)
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

const wallboardSseClients = new Set();
let lastWxccEvent = null;
let eventRefreshTimer = null;
let taskLegTerminationCache = {
  ts: 0,
  map: new Map(),
  inFlight: null
};
const TASK_LEG_TERMINATION_CACHE_TTL_MS = Number(process.env.TASK_LEG_TERMINATION_CACHE_TTL_MS || 15000);
let lastTaskDetailsQueryVariant = "base";

let wallboardDataCache = {
  updatedAt: 0,
  allAgents: [],
  allTasks: [],
  updating: null,
  error: null
};

async function getWallboardSourceData(force = false) {
  const now = Date.now();

  if (
    !force &&
    wallboardDataCache.updatedAt &&
    now - wallboardDataCache.updatedAt < WALLBOARD_DATA_CACHE_TTL_MS
  ) {
    return wallboardDataCache;
  }

  if (wallboardDataCache.updating) {
    return wallboardDataCache.updating;
  }

  wallboardDataCache.updating = Promise.all([
    getAgentSessions(),
    getTaskDetails()
  ])
    .then(([allAgents, allTasks]) => {
      wallboardDataCache.allAgents = allAgents;
      wallboardDataCache.allTasks = allTasks;
      wallboardDataCache.updatedAt = Date.now();
      wallboardDataCache.error = null;
      return wallboardDataCache;
    })
    .catch(err => {
      wallboardDataCache.error = err;
      throw err;
    })
    .finally(() => {
      wallboardDataCache.updating = null;
    });

  return wallboardDataCache.updating;
}

function getWrapupReasonFromTask(task) {
  return (
    task?.wrapUpReason ||
    task?.wrapupReason ||
    task?.wrapUpCodeName ||
    task?.wrapupCodeName ||
    task?.wrapUpCode ||
    task?.wrapupCode ||
    task?.wrapUpData?.name ||
    task?.wrapupData?.name ||
    task?.wrapUp?.name ||
    task?.wrapup?.name ||
    task?.wrapUpReasonName ||
    task?.wrapupReasonName ||
    ""
  );
}


async function getTaskLegTerminationMap(force = false) {
  const now = Date.now();

  if (!force && taskLegTerminationCache.map && now - taskLegTerminationCache.ts < TASK_LEG_TERMINATION_CACHE_TTL_MS) {
    return taskLegTerminationCache.map;
  }

  if (!force && taskLegTerminationCache.inFlight) {
    return taskLegTerminationCache.inFlight;
  }

  taskLegTerminationCache.inFlight = (async () => {
    const query = `
      query TaskLegTerminationMap($from: Long!, $to: Long!) {
        taskLegDetails(from: $from, to: $to) {
          taskLegs {
            id
            taskId
            status
            abandonedType
            terminationReason
            createdTime
            endedTime
          }
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, {
        from: now - 86400000,
        to: now
      });

      const taskLegs = result?.data?.taskLegDetails?.taskLegs || [];
      const map = new Map();

      for (const leg of taskLegs) {
        const taskId = leg?.taskId;
        if (!taskId) continue;

        const existing = map.get(taskId);
        const currentEnded = Number(leg.endedTime || 0);
        const existingEnded = Number(existing?.endedTime || 0);

        if (!existing || currentEnded >= existingEnded) {
          map.set(taskId, {
            terminationReason: leg.terminationReason || "",
            abandonedType: leg.abandonedType || "",
            taskLegId: leg.id || "",
            taskLegStatus: leg.status || "",
            taskLegCreatedTime: leg.createdTime || null,
            taskLegEndedTime: leg.endedTime || null
          });
        }
      }

      taskLegTerminationCache.ts = Date.now();
      taskLegTerminationCache.map = map;
      return map;
    } catch (err) {
      console.warn("TaskLeg termination map query failed, using cached/empty map:", err.message);

      // Important: Do not fail /api/wallboard if Search API rate-limits or errors.
      // Return last good cache if present. This prevents the widget from getting stuck.
      return taskLegTerminationCache.map || new Map();
    } finally {
      taskLegTerminationCache.inFlight = null;
    }
  })();

  return taskLegTerminationCache.inFlight;
}

async function callWxccRestDiscovery(method, path, body = null) {
  const token = await getValidServiceToken();

  const endpoint = /^https?:\/\//i.test(path)
    ? path
    : `${WXCC_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

  const response = await fetch(endpoint, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });

  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    endpoint,
    body: json,
    text: json ? undefined : text
  };
}


function getLiveTaskSeconds(task) {
  const now = Date.now();

  const candidates = [
    task?.connectedTime,
    task?.answeredTime,
    task?.lastStateChangeTime,
    task?.lastActivityTime,
    task?.createdTime
  ]
    .map(v => Number(v || 0))
    .filter(v => Number.isFinite(v) && v > 0);

  if (!candidates.length) return 0;

  // Use the newest available timestamp as best live start reference.
  return Math.max(0, Math.floor((now - Math.max(...candidates)) / 1000));
}

function getTaskDurationSeconds(task) {
  const totalDuration = Number(task?.totalDuration || 0);
  const connectedDuration = Number(task?.connectedDuration || 0);
  const queueDuration = Number(task?.queueDuration || 0);

  if (totalDuration > 0) return Math.round(totalDuration / 1000);
  if (connectedDuration > 0) return Math.round(connectedDuration / 1000);
  if (queueDuration > 0) return Math.round(queueDuration / 1000);

  return getLiveTaskSeconds(task);
}

async function buildWallboardPayload(session, forceRefresh = false) {
  const access = await getAllowedQueuesForSession(session);
  const allowedQueues = access.allowedQueues || [];
  const sourceData = await getWallboardSourceData(forceRefresh);

  const allAgents = sourceData.allAgents || [];
  const allTasks = sourceData.allTasks || [];

  const userTeamId = session?.user?.teamId || "";

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

  // Call history for the currently allowed voice queues.
  // getTaskDetails() already queries the last 24 hours.
  const callHistoryTasks = allowedQueueTasks
    .slice()
    .sort((a, b) => Number(b.createdTime || 0) - Number(a.createdTime || 0));

  const terminationByTaskId = await getTaskLegTerminationMap();

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

  return {
    ok: true,
    source: "webex-search-api",
    delivery: "sse-ready",
    queueSource: access.source,
    queueAccessError: access.error,
    userProfileId: access.user?.userProfileId || null,
    userProfileName: access.profile?.name || null,
    entryPointId: ENTRY_POINT_ID,
    teamId: userTeamId,
    generatedAt: new Date().toISOString(),
    allowedQueues,

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

    taskList: connectedTasks.map(task => {
      const liveHandleSeconds = getLiveTaskSeconds(task);
      const connectedSeconds = Math.round(Number(task.connectedDuration || 0) / 1000);

      return {
        id: task.id,
        status: task.status,
        caller: task.origin || "",
        queue: task?.lastQueue?.name || "",
        firstQueue: task?.firstQueueName || "",
        entryPoint: task?.lastEntryPoint?.name || "",
        agent: task?.lastAgent?.name || "",
        createdTime: task.createdTime || null,
        lastActivityTime: task.lastActivityTime || null,
        queueDuration: task.queueDuration || 0,
        connectedDuration: task.connectedDuration || 0,
        connectedStartTime: task.lastActivityTime || task.createdTime || null,
        liveHandleSeconds,
        handleSeconds: connectedSeconds > 0 ? connectedSeconds : liveHandleSeconds,
        handleBaseTimestamp: Date.now(),
        wrapupReason: getWrapupReasonFromTask(task),
        terminationReason: terminationByTaskId.get(task.id)?.terminationReason || "",
        taskLegId: terminationByTaskId.get(task.id)?.taskLegId || "",
        taskLegStatus: terminationByTaskId.get(task.id)?.taskLegStatus || ""
      };
    }),

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
        : 0,
      wrapupReason: getWrapupReasonFromTask(task)
    })),

    callHistoryList: callHistoryTasks.map(task => {
      const taskId = task.id || task.taskId || "";
      const termination = terminationByTaskId.get(taskId) || {};

      return {
        id: taskId,
        status: task.status,
        caller: task.origin || "",
        destination: task.destination || "",
        queue: task?.lastQueue?.name || "",
        firstQueue: task?.firstQueueName || "",
        entryPoint: task?.lastEntryPoint?.name || "",
        agent: task?.lastAgent?.name || "",
        createdTime: task.createdTime || null,
        endedTime: task.endedTime || null,
        queueDuration: task.queueDuration || 0,
        connectedDuration: task.connectedDuration || 0,
        totalDuration: task.totalDuration || 0,
        liveDurationSeconds: (() => {
          const totalMs = Number(task.totalDuration || 0);
          const createdMs = Number(task.createdTime || 0);
          const endedMs = Number(task.endedTime || 0);

          if (totalMs > 0) return Math.round(totalMs / 1000);
          if (createdMs > 0 && endedMs > 0 && endedMs >= createdMs) {
            return Math.round((endedMs - createdMs) / 1000);
          }
          if (String(task.status || "").toLowerCase() === "connected" && createdMs > 0) {
            return Math.max(0, Math.floor((Date.now() - createdMs) / 1000));
          }
          return 0;
        })(),
        durationSourcePolicy: "call-history-total-time-in-wxcc",
        isActive: task.isActive === true,
        isContactHandled: task.isContactHandled === true,
        abandonedType: task.abandonedType || "",
        contactHandleType: task.contactHandleType || "",
        handleType: task.contactHandleType || task.abandonedType || termination.abandonedType || "",
        wrapupReason: getWrapupReasonFromTask(task),
        terminationReason: termination.terminationReason || "",
        taskLegId: termination.taskLegId || "",
        taskLegStatus: termination.taskLegStatus || ""
      };
    })
  };
}

function writeSseEvent(res, eventName, payload) {
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcastSseEvent(eventName, payload) {
  for (const client of wallboardSseClients) {
    try {
      writeSseEvent(client.res, eventName, payload);
    } catch {
      wallboardSseClients.delete(client);
    }
  }
}

async function pushWallboardUpdateToClient(client, force = false) {
  try {
    const payload = await buildWallboardPayload(client.session, force);
    const serialized = JSON.stringify(payload);

    if (serialized !== client.lastPayload || force) {
      client.lastPayload = serialized;
      writeSseEvent(client.res, "wallboard", payload);
    }
  } catch (err) {
    writeSseEvent(client.res, "error", {
      ok: false,
      error: err.message
    });
  }
}

function scheduleEventDrivenWallboardRefresh(reason = "wxcc-event") {
  if (eventRefreshTimer) {
    clearTimeout(eventRefreshTimer);
  }

  const pushFreshWallboard = async refreshReason => {
    try {
      await getWallboardSourceData(true);

      for (const client of wallboardSseClients) {
        await pushWallboardUpdateToClient(client, true);
      }

      broadcastSseEvent("event-refresh", {
        ok: true,
        reason: refreshReason,
        generatedAt: new Date().toISOString(),
        clientCount: wallboardSseClients.size
      });
    } catch (err) {
      broadcastSseEvent("error", {
        ok: false,
        reason: refreshReason,
        error: err.message
      });
    }
  };

  eventRefreshTimer = setTimeout(() => {
    // WXCC sometimes publishes the webhook before the Search/State APIs are fully consistent.
    // Therefore we do an event-triggered retry burst. This is not continuous polling:
    // it only runs after a real WXCC event was received.
    EVENT_REFRESH_RETRY_DELAYS_MS.forEach((delay, index) => {
      setTimeout(() => {
        pushFreshWallboard(`${reason}:retry-${index + 1}`);
      }, delay);
    });
  }, EVENT_REFRESH_DEBOUNCE_MS);
}

function isWebhookSecretValid(req) {
  if (!WXCC_EVENT_WEBHOOK_SECRET) return true;

  const headerSecret =
    req.headers["x-wxcc-event-secret"] ||
    req.headers["x-webhook-secret"] ||
    req.headers["x-hook-secret"] ||
    req.headers["x-cisco-webex-contact-center-secret"];

  const querySecret = req.query?.secret;

  return String(headerSecret || querySecret || "") === WXCC_EVENT_WEBHOOK_SECRET;
}

app.get("/api/wallboard", requireSession, async (req, res) => {
  try {
    const payload = await buildWallboardPayload(req.session, false);
    res.json(payload);
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});


app.get("/api/wallboard/stream", async (req, res) => {
  const session = getSessionFromRequest(req);

  if (!session) {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }

  req.session = session;

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });

  if (typeof res.flushHeaders === "function") {
    res.flushHeaders();
  }

  const client = {
    id: crypto.randomUUID(),
    session,
    res,
    lastPayload: ""
  };

  wallboardSseClients.add(client);

  writeSseEvent(res, "ready", {
    ok: true,
    mode: WALLBOARD_FALLBACK_POLLING_ENABLED ? "event-bridge-with-fallback" : "event-only",
    generatedAt: new Date().toISOString(),
    fallbackPollingEnabled: WALLBOARD_FALLBACK_POLLING_ENABLED,
    fallbackRefreshMs: WALLBOARD_FALLBACK_POLLING_ENABLED ? WALLBOARD_DATA_CACHE_TTL_MS : null,
    eventRefreshDebounceMs: EVENT_REFRESH_DEBOUNCE_MS
  });

  // Initial load once when the widget connects.
  await pushWallboardUpdateToClient(client, true);

  const fallbackTimer = WALLBOARD_FALLBACK_POLLING_ENABLED
    ? setInterval(() => {
        pushWallboardUpdateToClient(client, false);
      }, WALLBOARD_DATA_CACHE_TTL_MS)
    : null;

  const heartbeatTimer = setInterval(() => {
    res.write(`: heartbeat ${Date.now()}\n\n`);
  }, SSE_HEARTBEAT_MS);

  req.on("close", () => {
    wallboardSseClients.delete(client);
    if (fallbackTimer) clearInterval(fallbackTimer);
    clearInterval(heartbeatTimer);
  });
});

app.post("/api/wxcc/events", (req, res) => {
  if (!isWebhookSecretValid(req)) {
    return res.status(401).json({
      ok: false,
      error: "Invalid webhook secret"
    });
  }

  lastWxccEvent = {
    receivedAt: new Date().toISOString(),
    headers: {
      event: req.headers["x-event-type"] || req.headers["x-webhook-event"] || "",
      resource: req.headers["x-resource"] || "",
      deliveryId: req.headers["x-webhook-delivery"] || req.headers["x-request-id"] || ""
    },
    body: req.body || {}
  };

  broadcastSseEvent("wxcc-event", {
    ok: true,
    receivedAt: lastWxccEvent.receivedAt,
    headers: lastWxccEvent.headers,
    eventBody: lastWxccEvent.body
  });

  scheduleEventDrivenWallboardRefresh(
    lastWxccEvent.headers.event || lastWxccEvent.body?.eventType || lastWxccEvent.body?.type || "wxcc-webhook"
  );

  res.json({
    ok: true,
    receivedAt: lastWxccEvent.receivedAt
  });
});

app.post("/api/wxcc/events/test", requireSession, (req, res) => {
  lastWxccEvent = {
    receivedAt: new Date().toISOString(),
    headers: {
      event: "manual-test",
      resource: "manual-test",
      deliveryId: crypto.randomUUID()
    },
    body: req.body || {}
  };

  broadcastSseEvent("wxcc-event", {
    ok: true,
    receivedAt: lastWxccEvent.receivedAt,
    headers: lastWxccEvent.headers
  });

  scheduleEventDrivenWallboardRefresh("manual-test");

  res.json({
    ok: true,
    message: "Manual event accepted. Wallboard refresh scheduled.",
    receivedAt: lastWxccEvent.receivedAt
  });
});

app.get("/api/debug/events", requireSession, (req, res) => {
  res.json({
    ok: true,
    sseClients: wallboardSseClients.size,
    lastWxccEvent,
    fallbackPollingEnabled: WALLBOARD_FALLBACK_POLLING_ENABLED,
    fallbackRefreshMs: WALLBOARD_FALLBACK_POLLING_ENABLED ? WALLBOARD_DATA_CACHE_TTL_MS : null,
    eventRefreshDebounceMs: EVENT_REFRESH_DEBOUNCE_MS,
    eventRefreshRetryDelaysMs: EVENT_REFRESH_RETRY_DELAYS_MS,
    webhookSecretConfigured: Boolean(WXCC_EVENT_WEBHOOK_SECRET)
  });
});



app.get("/api/debug/profile-queues", requireSession, async (req, res) => {
  try {
    const access = await getAllowedQueuesForSession(req.session);
    const config = await getAccessConfig(false);

    res.json({
      ok: true,
      sessionUser: req.session?.user || {},
      queueSource: access.source,
      queueAccessError: access.error,
      allowedQueues: access.allowedQueues,
      contactCenterUser: access.user ? {
        id: access.user.id,
        ciUserId: access.user.ciUserId,
        email: access.user.email,
        userProfileId: access.user.userProfileId,
        teamIds: access.user.teamIds
      } : null,
      userProfile: access.profile ? {
        id: access.profile.id,
        name: access.profile.name,
        profileType: access.profile.profileType,
        accessAllQueues: access.profile.accessAllQueues,
        queues: access.profile.queues,
        rawQueueRefsFound: collectQueueRefs(access.profile)
      } : null,
      allVoiceQueues: getAllTelephonyQueueNames(config.queues)
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});


function getSubscriptionEndpointUrl(path = WXCC_SUBSCRIPTION_ENDPOINT) {
  if (/^https?:\/\//i.test(path)) return path;
  if (path.startsWith("/")) return `${WEBEX_BASE_URL}${path}`;
  return `${WEBEX_BASE_URL}/${path}`;
}

function buildSubscriptionPayload(eventTypes = WXCC_SUBSCRIPTION_EVENTS) {
  const payload = {
    name: "WXCC Supervisor Widget Realtime Events",
    description: "Realtime events for the WXCC Supervisor Access Control widget",
    destinationUrl: WXCC_SUBSCRIPTION_TARGET_URL,
    eventTypes: Array.isArray(eventTypes) ? eventTypes : [eventTypes],
    orgId: WEBEX_ORG_ID
  };

  if (WXCC_EVENT_WEBHOOK_SECRET) {
    payload.secret = WXCC_EVENT_WEBHOOK_SECRET;
  }

  return payload;
}

async function callSubscriptionApi(method, path = WXCC_SUBSCRIPTION_ENDPOINT, body = null) {
  const token = await getValidServiceToken();

  const response = await fetch(getSubscriptionEndpointUrl(path), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });

  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    endpoint: getSubscriptionEndpointUrl(path),
    body: json,
    text: json ? undefined : text
  };
}

async function callWxccApi(method, path, body = null) {
  const token = await getValidServiceToken();

  const endpoint = getSubscriptionEndpointUrl(path);

  const response = await fetch(endpoint, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });

  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    endpoint,
    body: json,
    text: json ? undefined : text
  };
}

function extractEventTypesFromPayload(payload) {
  const values = new Set();

  function visit(value) {
    if (!value) return;

    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }

    if (typeof value !== "object") return;

    const candidate =
      value.eventType ||
      value.eventName ||
      value.type ||
      value.name ||
      value.id;

    if (candidate && typeof candidate === "string") {
      values.add(candidate);
    }

    for (const child of Object.values(value)) {
      if (typeof child === "object") visit(child);
    }
  }

  visit(payload);

  return [...values].sort();
}

async function discoverWxccEventTypes() {
  const results = [];

  for (const endpoint of WXCC_EVENT_TYPES_ENDPOINTS) {
    const result = await callWxccApi("GET", endpoint);
    results.push({
      endpoint: result.endpoint,
      ok: result.ok,
      status: result.status,
      eventTypes: result.body ? extractEventTypesFromPayload(result.body) : [],
      body: result.body,
      text: result.text
    });
  }

  return results;
}


async function createWxccSubscription(eventTypes = WXCC_SUBSCRIPTION_EVENTS) {
  const payload = buildSubscriptionPayload(eventTypes);
  const result = await callSubscriptionApi("POST", WXCC_SUBSCRIPTION_ENDPOINT, payload);

  return {
    eventTypes: payload.eventTypes,
    payload,
    result
  };
}

app.get("/api/admin/wxcc-subscriptions/config", requireSession, requireWriteRole, (req, res) => {
  res.json({
    ok: true,
    buildId: BUILD_ID,
    endpoint: getSubscriptionEndpointUrl(),
    targetUrl: WXCC_SUBSCRIPTION_TARGET_URL,
    events: WXCC_SUBSCRIPTION_EVENTS,
    webhookSecretConfigured: Boolean(WXCC_EVENT_WEBHOOK_SECRET),
    expectedPayload: WXCC_SUBSCRIPTION_EVENTS.length ? buildSubscriptionPayload(WXCC_SUBSCRIPTION_EVENTS) : null,
    eventTypeDiscoveryEndpoints: WXCC_EVENT_TYPES_ENDPOINTS.map(getSubscriptionEndpointUrl)
  });
});

app.get("/api/admin/wxcc-subscriptions", requireSession, requireWriteRole, async (req, res) => {
  try {
    const result = await callSubscriptionApi("GET", WXCC_SUBSCRIPTION_ENDPOINT);

    res.status(result.ok ? 200 : result.status).json({
      ok: result.ok,
      endpoint: result.endpoint,
      status: result.status,
      body: result.body,
      text: result.text
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

app.post("/api/admin/create-wxcc-subscriptions", requireSession, requireWriteRole, async (req, res) => {
  try {
    const requestedEvents = Array.isArray(req.body?.events) && req.body.events.length
      ? req.body.events.map(v => String(v).trim()).filter(Boolean)
      : WXCC_SUBSCRIPTION_EVENTS;

    if (!requestedEvents.length) {
      return res.status(400).json({
        ok: false,
        error: "No WXCC subscription event types configured. Call GET /api/admin/wxcc-event-types first, then set WXCC_SUBSCRIPTION_EVENTS or pass { events: [...] } in the POST body.",
        endpoint: getSubscriptionEndpointUrl(),
        targetUrl: WXCC_SUBSCRIPTION_TARGET_URL
      });
    }

    const result = await createWxccSubscription(requestedEvents);

    res.status(result.result.ok ? 200 : result.result.status).json({
      ok: result.result.ok,
      endpoint: getSubscriptionEndpointUrl(),
      targetUrl: WXCC_SUBSCRIPTION_TARGET_URL,
      events: requestedEvents,
      webhookSecretConfigured: Boolean(WXCC_EVENT_WEBHOOK_SECRET),
      payload: result.payload,
      result: result.result
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

app.post("/api/admin/test-wxcc-event-bridge", requireSession, requireWriteRole, (req, res) => {
  lastWxccEvent = {
    receivedAt: new Date().toISOString(),
    headers: {
      event: "admin-test",
      resource: "admin-test",
      deliveryId: crypto.randomUUID()
    },
    body: req.body || {}
  };

  broadcastSseEvent("wxcc-event", {
    ok: true,
    receivedAt: lastWxccEvent.receivedAt,
    headers: lastWxccEvent.headers
  });

  scheduleEventDrivenWallboardRefresh("admin-test");

  res.json({
    ok: true,
    message: "Admin test event accepted. Wallboard refresh scheduled.",
    receivedAt: lastWxccEvent.receivedAt
  });
});


app.get("/api/debug/build", (req, res) => {
  res.json({
    ok: true,
    buildId: BUILD_ID,
    hasEventTypesEndpoint: true,
    hasSubscriptionConfigEndpoint: true,
    hasEventBridge: true,
    focusResumeRefreshFix: true,
    historyConnectedStaleFix: true,
    sseWatchdogStabilityFix: true,
    durationPolicyStableFix: true,
    frontendTimerHistoryCacheFix: true,
    clientLiveTimerEnabled: true,
    taskLegTerminationCacheEnabled: true,
    taskLegTerminationEnabled: true,
    taskLegTerminationCacheEnabled: true,
    analyzerReportDiscoveryEnabled: true,
    csrReportTodayDebugEnabled: true,
    searchSchemaDebugEnabled: true,
    eventOnlyRealtime: true,
    eventTriggeredRetryBurst: true,
    callVisibilityRetryOptimized: true,
    callHistoryEnabled: true,
    callHistoryWrapupEnabled: true,
    callHistoryHandleTypeEnabled: true,
    wrapupDiscoveryEnabled: true,
    csrReportTodayDebugEnabled: true,
    searchSchemaDebugEnabled: true,
    callHistoryFullWidth: true,
    taskDetailsWrapupVariant: lastTaskDetailsQueryVariant,
    callHistoryWindow: "last-24h",
    defaultEventRefreshDebounceMs: 1200,
    eventRefreshRetryDelaysMs: EVENT_REFRESH_RETRY_DELAYS_MS,
    fallbackPollingEnabled: WALLBOARD_FALLBACK_POLLING_ENABLED,
    expectedEventTypesPath: "/api/admin/wxcc-event-types"
  });
});

app.get("/api/admin/wxcc-event-types", requireSession, requireWriteRole, async (req, res) => {
  try {
    const results = await discoverWxccEventTypes();

    res.json({
      ok: true,
      buildId: BUILD_ID,
      configuredEventTypes: WXCC_SUBSCRIPTION_EVENTS,
      discoveryEndpoints: WXCC_EVENT_TYPES_ENDPOINTS.map(getSubscriptionEndpointUrl),
      results
    });
  } catch (err) {
    res.status(500).json({ ok: false, buildId: BUILD_ID, error: err.message });
  }
});

app.get("/api/admin/wxcc-eventtypes", requireSession, requireWriteRole, async (req, res) => {
  try {
    const results = await discoverWxccEventTypes();

    res.json({
      ok: true,
      buildId: BUILD_ID,
      alias: "/api/admin/wxcc-eventtypes",
      configuredEventTypes: WXCC_SUBSCRIPTION_EVENTS,
      discoveryEndpoints: WXCC_EVENT_TYPES_ENDPOINTS.map(getSubscriptionEndpointUrl),
      results
    });
  } catch (err) {
    res.status(500).json({ ok: false, buildId: BUILD_ID, error: err.message });
  }
});

app.get("/api/admin/event-types", requireSession, requireWriteRole, async (req, res) => {
  try {
    const results = await discoverWxccEventTypes();

    res.json({
      ok: true,
      buildId: BUILD_ID,
      alias: "/api/admin/event-types",
      configuredEventTypes: WXCC_SUBSCRIPTION_EVENTS,
      discoveryEndpoints: WXCC_EVENT_TYPES_ENDPOINTS.map(getSubscriptionEndpointUrl),
      results
    });
  } catch (err) {
    res.status(500).json({ ok: false, buildId: BUILD_ID, error: err.message });
  }
});


app.get("/api/debug/task-sample", requireSession, requireWriteRole, async (req, res) => {
  try {
    const tasks = await getTaskDetails();
    const sample = tasks.slice(0, 5);

    res.json({
      ok: true,
      buildId: BUILD_ID,
      lastTaskDetailsQueryVariant,
      count: tasks.length,
      sample
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});



function summarizeSearchResult(result, maxRows = 5) {
  const summary = {
    keys: result && typeof result === "object" ? Object.keys(result) : [],
    sample: null
  };

  function findArrays(value, path = []) {
    const arrays = [];

    if (!value || typeof value !== "object") return arrays;

    if (Array.isArray(value)) {
      arrays.push({
        path: path.join(".") || "root",
        length: value.length,
        sample: value.slice(0, maxRows)
      });
      return arrays;
    }

    for (const [key, child] of Object.entries(value)) {
      arrays.push(...findArrays(child, [...path, key]));
    }

    return arrays;
  }

  summary.arrays = findArrays(result);
  return summary;
}

async function runWrapupDiscoveryQuery(name, query, variables) {
  try {
    const result = await postSearchQuery(query, variables);

    return {
      name,
      ok: true,
      summary: summarizeSearchResult(result),
      raw: result
    };
  } catch (err) {
    return {
      name,
      ok: false,
      error: err.message
    };
  }
}

app.get("/api/debug/wrapup-discovery", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const queries = [
    {
      name: "customerActivityRecords",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          customerActivityRecords(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              queueName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              createdTime
              endedTime
            }
          }
        }
      `
    },
    {
      name: "customerActivityRecord",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          customerActivityRecord(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              queueName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              createdTime
              endedTime
            }
          }
        }
      `
    },
    {
      name: "contactSession",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          contactSession(from: $from, to: $to) {
            sessions {
              contactSessionId
              taskId
              queueName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              createdTime
              endedTime
            }
          }
        }
      `
    },
    {
      name: "contactSessions",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          contactSessions(from: $from, to: $to) {
            sessions {
              contactSessionId
              taskId
              queueName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              createdTime
              endedTime
            }
          }
        }
      `
    },
    {
      name: "wrapupReports",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          wrapupReports(from: $from, to: $to) {
            records {
              agentName
              teamName
              queueName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              count
              createdTime
            }
          }
        }
      `
    },
    {
      name: "wrapUpReports",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          wrapUpReports(from: $from, to: $to) {
            records {
              agentName
              teamName
              queueName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              count
              createdTime
            }
          }
        }
      `
    },
    {
      name: "taskDetailsWithPotentialWrapupFields",
      query: `
        query WrapupDiscovery($from: Long!, $to: Long!) {
          taskDetails(from: $from, to: $to) {
            tasks {
              id
              status
              channelType
              createdTime
              endedTime
              firstQueueName
              contactHandleType
              abandonedType
              wrapUpReason
              wrapupReason
              wrapUpCodeName
              wrapupCodeName
              wrapUpCode
              wrapupCode
              wrapUpReasonName
              wrapupReasonName
              lastQueue { id name }
              lastAgent { id name }
            }
          }
        }
      `
    }
  ];

  const results = [];

  for (const item of queries) {
    results.push(await runWrapupDiscoveryQuery(item.name, item.query, variables));
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    from: variables.from,
    to: variables.to,
    note: "This endpoint tests candidate Analyzer/Search GraphQL contexts for per-call wrap-up fields. Failed queries are expected during discovery.",
    results
  });
});



function getTodayRange(timeZone = "Europe/Berlin") {
  // Render läuft typischerweise in UTC. Für den Debug nehmen wir bewusst lokale Browser/Server-Logik
  // plus einen Tagesbereich, der den aktuellen Tag großzügig abdeckt.
  const now = new Date();
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);

  return {
    from: start.getTime(),
    to: now.getTime(),
    timeZone
  };
}

function summarizeCsrResult(result, maxRows = 5) {
  function findArrays(value, path = []) {
    const arrays = [];

    if (!value || typeof value !== "object") return arrays;

    if (Array.isArray(value)) {
      arrays.push({
        path: path.join(".") || "root",
        length: value.length,
        sample: value.slice(0, maxRows)
      });
      return arrays;
    }

    for (const [key, child] of Object.entries(value)) {
      arrays.push(...findArrays(child, [...path, key]));
    }

    return arrays;
  }

  return {
    keys: result && typeof result === "object" ? Object.keys(result) : [],
    arrays: findArrays(result)
  };
}

async function runCsrDiscoveryQuery(name, query, variables) {
  try {
    const result = await postSearchQuery(query, variables);

    return {
      name,
      ok: true,
      summary: summarizeCsrResult(result),
      raw: result
    };
  } catch (err) {
    return {
      name,
      ok: false,
      error: err.message
    };
  }
}


app.get("/api/debug/csr-report-today", requireSession, requireWriteRole, async (req, res) => {
  const range = getTodayRange("Europe/Berlin");
  const variables = {
    from: range.from,
    to: range.to
  };

  const queries = [
    {
      name: "csrReport",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          csrReport(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              interactionId
              channelType
              origin
              destination
              direction
              queueName
              entryPointName
              siteName
              teamName
              agentName
              wrapUpReason
              wrapupReason
              wrapUpCodeName
              wrapupCodeName
              wrapUpCode
              wrapupCode
              contactHandleType
              abandonedType
              createdTime
              connectedTime
              endedTime
              queueDuration
              connectedDuration
              totalDuration
            }
          }
        }
      `
    },
    {
      name: "csrReports",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          csrReports(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              interactionId
              channelType
              origin
              destination
              direction
              queueName
              entryPointName
              siteName
              teamName
              agentName
              wrapUpReason
              wrapupReason
              wrapUpCodeName
              wrapupCodeName
              wrapUpCode
              wrapupCode
              contactHandleType
              abandonedType
              createdTime
              connectedTime
              endedTime
              queueDuration
              connectedDuration
              totalDuration
            }
          }
        }
      `
    },
    {
      name: "customerSessionRecords",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          customerSessionRecords(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              interactionId
              channelType
              origin
              destination
              direction
              queueName
              entryPointName
              teamName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              abandonedType
              createdTime
              endedTime
              totalDuration
            }
          }
        }
      `
    },
    {
      name: "customerSessionRecord",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          customerSessionRecord(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              interactionId
              channelType
              origin
              destination
              direction
              queueName
              entryPointName
              teamName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              abandonedType
              createdTime
              endedTime
              totalDuration
            }
          }
        }
      `
    },
    {
      name: "contactSessionRecords",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          contactSessionRecords(from: $from, to: $to) {
            records {
              contactSessionId
              recordId
              recordUniqueId
              taskId
              interactionId
              channelType
              origin
              destination
              direction
              queueName
              entryPointName
              teamName
              agentName
              wrapUpCodeName
              wrapupCodeName
              wrapUpReason
              wrapupReason
              contactHandleType
              abandonedType
              createdTime
              endedTime
              totalDuration
            }
          }
        }
      `
    },
    {
      name: "csrReportMinimal",
      query: `
        query CsrReportToday($from: Long!, $to: Long!) {
          csrReport(from: $from, to: $to) {
            records {
              contactSessionId
              taskId
              queueName
              agentName
              wrapUpCodeName
              contactHandleType
              createdTime
              endedTime
            }
          }
        }
      `
    }
  ];

  const results = [];

  for (const item of queries) {
    results.push(await runCsrDiscoveryQuery(item.name, item.query, variables));
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    report: "CSR Report - Today discovery",
    from: variables.from,
    to: variables.to,
    timeZone: range.timeZone,
    note: "This endpoint tests likely Search/Analyzer GraphQL contexts for the CSR Report with today's duration. Failed queries are expected during discovery.",
    results
  });
});


function unwrapGraphqlType(type) {
  if (!type) return "";

  if (type.kind === "NON_NULL") {
    return `${unwrapGraphqlType(type.ofType)}!`;
  }

  if (type.kind === "LIST") {
    return `[${unwrapGraphqlType(type.ofType)}]`;
  }

  return type.name || type.kind || "";
}

function summarizeGraphqlField(field) {
  return {
    name: field.name,
    type: unwrapGraphqlType(field.type),
    args: (field.args || []).map(arg => ({
      name: arg.name,
      type: unwrapGraphqlType(arg.type)
    }))
  };
}

app.get("/api/debug/search-schema", requireSession, requireWriteRole, async (req, res) => {
  const query = `
    query SearchSchemaIntrospection {
      __schema {
        queryType {
          fields {
            name
            type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
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
            args {
              name
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
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
            }
          }
        }
      }
    }
  `;

  try {
    const result = await postSearchQuery(query, {});
    const fields = result?.data?.__schema?.queryType?.fields || [];
    const summarizedFields = fields.map(summarizeGraphqlField);

    const keywords = [
      "csr",
      "customer",
      "contact",
      "session",
      "activity",
      "record",
      "wrap",
      "wrapup",
      "wrapUp",
      "aux",
      "auxiliary",
      "agent",
      "task"
    ];

    const interestingFields = summarizedFields.filter(field => {
      const haystack = `${field.name} ${field.type}`.toLowerCase();
      return keywords.some(keyword => haystack.includes(keyword.toLowerCase()));
    });

    res.json({
      ok: true,
      buildId: BUILD_ID,
      fieldCount: summarizedFields.length,
      interestingFieldCount: interestingFields.length,
      interestingFields,
      allFields: summarizedFields
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message,
      note: "If introspection is disabled, we need to discover the Analyzer report API via REST/report definitions instead."
    });
  }
});

app.get("/api/debug/search-field-candidates", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const candidates = [
    "agentWrapupAuxiliary",
    "agentWrapUpAuxiliary",
    "agentWrapupAuxiliaryReport",
    "agentWrapUpAuxiliaryReport",
    "agentWrapup",
    "agentWrapUp",
    "wrapupAuxiliary",
    "wrapUpAuxiliary",
    "wrapupAuxiliaryReport",
    "wrapUpAuxiliaryReport",
    "agentAuxiliary",
    "agentAuxiliaryReport",
    "csr",
    "CSR",
    "csrReport",
    "customerSession",
    "customerSessions",
    "customerActivity",
    "customerActivities",
    "customerActivityRecord",
    "customerActivityRecords"
  ];

  const results = [];

  for (const field of candidates) {
    const query = `
      query Candidate($from: Long!, $to: Long!) {
        ${field}(from: $from, to: $to) {
          __typename
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, variables);
      results.push({
        field,
        ok: true,
        result
      });
    } catch (err) {
      results.push({
        field,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    note: "This probes likely report/query field names with a minimal __typename selection.",
    results
  });
});



function summarizeTaskLegResult(result, maxRows = 5) {
  function findArrays(value, path = []) {
    const arrays = [];

    if (!value || typeof value !== "object") return arrays;

    if (Array.isArray(value)) {
      arrays.push({
        path: path.join(".") || "root",
        length: value.length,
        sample: value.slice(0, maxRows)
      });
      return arrays;
    }

    for (const [key, child] of Object.entries(value)) {
      arrays.push(...findArrays(child, [...path, key]));
    }

    return arrays;
  }

  return {
    keys: result && typeof result === "object" ? Object.keys(result) : [],
    arrays: findArrays(result)
  };
}

async function runTaskLegDiscoveryQuery(name, query, variables) {
  try {
    const result = await postSearchQuery(query, variables);

    return {
      name,
      ok: true,
      summary: summarizeTaskLegResult(result),
      raw: result
    };
  } catch (err) {
    return {
      name,
      ok: false,
      error: err.message
    };
  }
}


app.get("/api/debug/taskleg-schema", requireSession, requireWriteRole, async (req, res) => {
  const query = `
    query TaskLegDetailsTypeOnly {
      __type(name: "TaskLegDetails") {
        name
        kind
        fields {
          name
          type {
            kind
            name
            ofType {
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
    }
  `;

  try {
    const result = await postSearchQuery(query, {});
    const fields = result?.data?.__type?.fields || [];

    const normalizedFields = fields.map(field => ({
      name: field.name,
      type: unwrapGraphqlType(field.type)
    }));

    const keywords = [
      "wrap", "reason", "disconnect", "disposition", "termination",
      "ended", "end", "handle", "agent", "queue", "task", "session",
      "leg", "contact", "code"
    ];

    const interestingFields = normalizedFields.filter(field => {
      const haystack = `${field.name} ${field.type}`.toLowerCase();
      return keywords.some(keyword => haystack.includes(keyword));
    });

    res.json({
      ok: true,
      buildId: BUILD_ID,
      note: "Light introspection only. This avoids Cisco's anti-abuse protection for deep introspection.",
      detailType: {
        name: result?.data?.__type?.name || "TaskLegDetails",
        fieldCount: normalizedFields.length,
        interestingFields,
        allFields: normalizedFields
      }
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});

app.get("/api/debug/taskleg-sample", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const queries = [
    {
      name: "minimal",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            tasks { id }
          }
        }
      `
    },
    {
      name: "commonFields",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            tasks {
              id
              status
              channelType
              createdTime
              endedTime
              origin
              destination
              direction
              queueDuration
              connectedDuration
              totalDuration
              contactHandleType
              abandonedType
              firstQueueName
              lastQueue { id name }
              lastAgent { id name }
              lastTeam { id name }
            }
          }
        }
      `
    },
    {
      name: "handleFields",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            tasks {
              id
              contactHandleType
              abandonedType
            }
          }
        }
      `
    },
    {
      name: "taskLegsNode",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            taskLegs { id }
          }
        }
      `
    },
    {
      name: "recordsNode",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            records { id }
          }
        }
      `
    }
  ];

  const results = [];

  for (const item of queries) {
    results.push(await runTaskLegDiscoveryQuery(item.name, item.query, variables));
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    from: variables.from,
    to: variables.to,
    note: "This probes taskLegDetails shape and wrapup/disconnect candidates. Failed variants are expected.",
    results
  });
});


app.get("/api/debug/taskleg-field-probe", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const candidateFields = [
    "id",
    "taskId",
    "status",
    "channelType",
    "createdTime",
    "endedTime",
    "origin",
    "destination",
    "direction",
    "queueName",
    "agentName",
    "contactHandleType",
    "abandonedType",
    "wrapUpReason",
    "wrapupReason",
    "wrapUpCodeName",
    "wrapupCodeName",
    "wrapUpCode",
    "wrapupCode",
    "wrapUpReasonName",
    "wrapupReasonName",
    "disconnectReason",
    "endReason",
    "reason",
    "disposition",
    "dispositionCode",
    "dispositionName"
  ];

  const results = [];

  for (const fieldName of candidateFields) {
    const query = `
      query TaskLegFieldProbe($from: Long!, $to: Long!) {
        taskLegDetails(from: $from, to: $to) {
          tasks {
            ${fieldName}
          }
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, variables);
      const tasks = result?.data?.taskLegDetails?.tasks || [];
      results.push({
        fieldName,
        ok: true,
        count: tasks.length,
        sample: tasks.slice(0, 3)
      });
    } catch (err) {
      results.push({
        fieldName,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    note: "This probes TaskLegDetails fields one-by-one to find supported wrapup/disposition fields without heavy introspection.",
    results
  });
});


app.get("/api/debug/taskleg-rootnode-probe", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const candidateNodes = [
    "data",
    "items",
    "records",
    "results",
    "nodes",
    "edges",
    "taskLegs",
    "legs",
    "taskLegDetails",
    "taskLeg",
    "rows",
    "list",
    "content"
  ];

  const results = [];

  for (const nodeName of candidateNodes) {
    const query = `
      query TaskLegRootNodeProbe($from: Long!, $to: Long!) {
        taskLegDetails(from: $from, to: $to) {
          ${nodeName} {
            __typename
          }
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, variables);
      results.push({
        nodeName,
        ok: true,
        result
      });
    } catch (err) {
      results.push({
        nodeName,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    from: variables.from,
    to: variables.to,
    note: "This probes possible child/root nodes below taskLegDetails. We need the node that is not FieldUndefined.",
    results
  });
});

app.get("/api/debug/taskleg-rootfield-schema", requireSession, requireWriteRole, async (req, res) => {
  const query = `
    query TaskLegListTypeOnly {
      __type(name: "TaskLegDetailsList") {
        name
        fields {
          name
          type {
            kind
            name
            ofType {
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
    }
  `;

  try {
    const result = await postSearchQuery(query, {});
    const fields = result?.data?.__type?.fields || [];

    res.json({
      ok: true,
      buildId: BUILD_ID,
      fields: fields.map(field => ({
        name: field.name,
        type: unwrapGraphqlType(field.type)
      }))
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});


app.get("/api/debug/taskleg-field-probe-v2", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const candidateFields = [
    "id",
    "taskId",
    "status",
    "channelType",
    "createdTime",
    "endedTime",
    "origin",
    "destination",
    "direction",
    "queueName",
    "agentName",
    "teamName",
    "siteName",
    "contactHandleType",
    "abandonedType",
    "wrapUpReason",
    "wrapupReason",
    "wrapUpCodeName",
    "wrapupCodeName",
    "wrapUpCode",
    "wrapupCode",
    "wrapUpReasonName",
    "wrapupReasonName",
    "disconnectReason",
    "endReason",
    "reason",
    "disposition",
    "dispositionCode",
    "dispositionName",
    "terminationReason",
    "terminationType",
    "queueDuration",
    "connectedDuration",
    "totalDuration",
    "lastQueue",
    "lastAgent",
    "lastTeam"
  ];

  const results = [];

  for (const fieldName of candidateFields) {
    const query = `
      query TaskLegFieldProbe($from: Long!, $to: Long!) {
        taskLegDetails(from: $from, to: $to) {
          taskLegs {
            ${fieldName}
          }
        }
      }
    `;

    try {
      const result = await postSearchQuery(query, variables);
      const taskLegs = result?.data?.taskLegDetails?.taskLegs || [];
      results.push({
        fieldName,
        ok: true,
        count: taskLegs.length,
        sample: taskLegs.slice(0, 3)
      });
    } catch (err) {
      results.push({
        fieldName,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    from: variables.from,
    to: variables.to,
    note: "Fixed probe: taskLegDetails.taskLegs is the valid root node.",
    results
  });
});

app.get("/api/debug/taskleg-sample-v2", requireSession, requireWriteRole, async (req, res) => {
  const now = Date.now();
  const variables = {
    from: now - 86400000,
    to: now
  };

  const queries = [
    {
      name: "minimal",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            taskLegs {
              id
            }
          }
        }
      `
    },
    {
      name: "commonSupportedCandidates",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            taskLegs {
              id
              taskId
              status
              channelType
              createdTime
              endedTime
              contactHandleType
              abandonedType
            }
          }
        }
      `
    },
    {
      name: "wrapupCandidatesSmall1",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            taskLegs {
              id
              wrapUpReason
              wrapupReason
              wrapUpCodeName
              wrapupCodeName
            }
          }
        }
      `
    },
    {
      name: "wrapupCandidatesSmall2",
      query: `
        query TaskLegSample($from: Long!, $to: Long!) {
          taskLegDetails(from: $from, to: $to) {
            taskLegs {
              id
              disconnectReason
              endReason
              disposition
              dispositionName
            }
          }
        }
      `
    }
  ];

  const results = [];

  for (const item of queries) {
    results.push(await runTaskLegDiscoveryQuery(item.name, item.query, variables));
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    from: variables.from,
    to: variables.to,
    note: "Fixed sample: taskLegDetails.taskLegs is the valid root node.",
    results
  });
});


app.get("/api/debug/analyzer-report-discovery", requireSession, requireWriteRole, async (req, res) => {
  const candidates = [
    "/v1/reports",
    "/v1/report",
    "/v1/reports/definitions",
    "/v1/report-definitions",
    "/v1/analyzer/reports",
    "/v1/analyzer/report-definitions",
    "/v1/analyzer/stock-reports",
    "/v1/stock-reports",
    "/v1/custom-reports",
    "/v1/reporting/reports",
    "/v1/reporting/report-definitions",
    "/v1/reporting/analyzer/reports"
  ];

  const results = [];

  for (const path of candidates) {
    try {
      const result = await callWxccRestDiscovery("GET", path);
      results.push({
        path,
        ok: result.ok,
        status: result.status,
        endpoint: result.endpoint,
        body: result.body,
        text: result.text
      });
    } catch (err) {
      results.push({
        path,
        ok: false,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    buildId: BUILD_ID,
    note: "This probes likely REST endpoints for Analyzer/Report definitions. We are looking for CSR Report or Agent WrapUp Auxiliary.",
    results
  });
});

app.get("/api/debug/taskleg-termination-sample", requireSession, requireWriteRole, async (req, res) => {
  try {
    const map = await getTaskLegTerminationMap();

    res.json({
      ok: true,
      buildId: BUILD_ID,
      count: map.size,
      sample: Array.from(map.entries()).slice(0, 10).map(([taskId, value]) => ({
        taskId,
        ...value
      }))
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});



app.get("/api/debug/call-history-payload", requireSession, requireWriteRole, async (req, res) => {
  try {
    const data = await buildWallboardPayload(req.session || {});
    res.json({
      ok: true,
      buildId: BUILD_ID,
      count: Array.isArray(data.callHistoryList) ? data.callHistoryList.length : 0,
      sample: Array.isArray(data.callHistoryList) ? data.callHistoryList.slice(0, 10) : []
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});



app.get("/api/debug/termination-cache", requireSession, requireWriteRole, async (req, res) => {
  res.json({
    ok: true,
    buildId: BUILD_ID,
    ttlMs: TASK_LEG_TERMINATION_CACHE_TTL_MS,
    cacheAgeMs: taskLegTerminationCache.ts ? Date.now() - taskLegTerminationCache.ts : null,
    cacheCount: taskLegTerminationCache.map ? taskLegTerminationCache.map.size : 0,
    inFlight: !!taskLegTerminationCache.inFlight
  });
});



app.get("/api/debug/live-duration-payload", requireSession, requireWriteRole, async (req, res) => {
  try {
    const data = await buildWallboardPayload(req.session || {});
    res.json({
      ok: true,
      buildId: BUILD_ID,
      activeCalls: data.taskList || [],
      callHistorySample: Array.isArray(data.callHistoryList) ? data.callHistoryList.slice(0, 5) : []
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      buildId: BUILD_ID,
      error: err.message
    });
  }
});


app.listen(PORT, () => {
  console.log(`Secure widget backend listening on ${PORT}`);
});
