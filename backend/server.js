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

app.get("/api/wallboard", requireSession, async (req, res) => {
  try {
    const access = await getAllowedQueuesForSession(req.session);
    const allowedQueues = access.allowedQueues || [];

    const [allAgents, allTasks] = await Promise.all([
      getAgentSessions(),
      getTaskDetails()
    ]);

    const userTeamId = req.session?.user?.teamId || "";

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

app.listen(PORT, () => {
  console.log(`Secure widget backend listening on ${PORT}`);
});
