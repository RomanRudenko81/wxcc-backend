import { Desktop } from "@wxcc-desktop/sdk";

const API_URL = "https://wxcc-backend.onrender.com";
const ENTRY_POINT_ID = "284cd09a-eef4-40a2-82c6-53d08705e3e3";
const POLL_INTERVAL_MS = 5000;

let sessionToken = null;
let currentRole = "viewer";
let isUpdating = false;
let isBootstrapping = false;
let pollHandle = null;
let resolvedIdentity = null;
let sdkInitialized = false;
let identitySource = "none";

function setOutput(payload) {
  const output = document.getElementById("output");
  output.textContent = JSON.stringify(payload, null, 2);
}

function safeSnapshot(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return { note: "Snapshot could not be serialized" };
  }
}

async function initDesktopSdk() {
  if (sdkInitialized) return;

  try {
    Desktop.config.init();
    sdkInitialized = true;
  } catch (error) {
    throw new Error(`WXCC SDK init failed: ${error.message}`);
  }
}

function pickIdentityFromSdk(latestData = {}) {
  const candidates = [
    {
      email: latestData?.agentProfile?.email,
      userId: latestData?.agentProfile?.id,
      teamId: latestData?.agentProfile?.teamId,
      displayName: latestData?.agentProfile?.displayName
    },
    {
      email: latestData?.agentInfo?.email,
      userId: latestData?.agentInfo?.id,
      teamId: latestData?.agentInfo?.teamId,
      displayName: latestData?.agentInfo?.displayName
    },
    {
      email: latestData?.email,
      userId: latestData?.userId,
      teamId: latestData?.teamId,
      displayName: latestData?.displayName || latestData?.name || latestData?.agentName
    }
  ];

  for (const candidate of candidates) {
    const normalized = {
      email: candidate.email || "",
      userId: candidate.userId || "",
      teamId: candidate.teamId || "",
      displayName: candidate.displayName || ""
    };

    if (normalized.email || normalized.userId || normalized.displayName) {
      return normalized;
    }
  }

  return {
    email: "",
    userId: "",
    teamId: "",
    displayName: ""
  };
}

async function resolveDesktopIdentity() {
  try {
    await initDesktopSdk();

    const latestData = Desktop?.agentStateInfo?.latestData || {};
    const sdkIdentity = pickIdentityFromSdk(latestData);

    if (sdkIdentity.email || sdkIdentity.userId || sdkIdentity.displayName) {
      resolvedIdentity = sdkIdentity;
      identitySource = "wxcc-sdk";
      return {
        identity: sdkIdentity,
        sdkSnapshot: safeSnapshot(latestData)
      };
    }

    resolvedIdentity = {
      email: "",
      userId: "",
      teamId: "",
      displayName: ""
    };
    identitySource = "sdk-empty";
    return {
      identity: resolvedIdentity,
      sdkSnapshot: safeSnapshot(latestData)
    };
  } catch (sdkError) {
    resolvedIdentity = {
      email: "",
      userId: "",
      teamId: "",
      displayName: ""
    };
    identitySource = "sdk-init-failed";

    return {
      identity: resolvedIdentity,
      sdkSnapshot: {
        sdkError: sdkError.message
      }
    };
  }
}

function renderDebugInfo(extra = {}) {
  setOutput({
    identitySource,
    localIdentity: resolvedIdentity || {
      email: "",
      userId: "",
      teamId: "",
      displayName: ""
    },
    currentRole,
    hasSessionToken: Boolean(sessionToken),
    ...extra
  });
}

function applyRoleState() {
  const writable = currentRole === "supervisor" || currentRole === "admin";

  document.getElementById("emergencyToggle").disabled = !writable;
  document.getElementById("prompt").disabled = !writable;
  document.getElementById("saveBtn").disabled = !writable;
}

async function readJsonResponse(res) {
  const text = await res.text();

  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

async function bootstrapSession() {
  if (isBootstrapping) return;
  isBootstrapping = true;

  try {
    const { identity, sdkSnapshot } = await resolveDesktopIdentity();

    const res = await fetch(`${API_URL}/api/session/bootstrap`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(identity)
    });

    const data = await readJsonResponse(res);

    if (!res.ok) {
      renderDebugInfo({
        bootstrapHttpStatus: res.status,
        bootstrapError: data,
        sdkSnapshot
      });
      throw new Error(data.error || "Session bootstrap failed");
    }

    if (!data.sessionToken) {
      renderDebugInfo({
        bootstrapHttpStatus: res.status,
        bootstrapError: data,
        sdkSnapshot
      });
      throw new Error("Bootstrap response did not include a session token");
    }

    sessionToken = data.sessionToken;
    currentRole = data.role || "viewer";

    document.getElementById("userInfo").textContent =
      `${data.user?.displayName || "Unknown"}${data.user?.email ? " (" + data.user.email + ")" : ""}`;
    document.getElementById("roleBadge").textContent = currentRole.toUpperCase();

    applyRoleState();

    renderDebugInfo({
      bootstrapResponse: data,
      sdkSnapshot
    });
  } finally {
    isBootstrapping = false;
  }
}

async function authorizedFetch(path, options = {}, retryOn401 = true) {
  if (!sessionToken) {
    await bootstrapSession();
  }

  const makeRequest = async () =>
    fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${sessionToken}`
      }
    });

  let res = await makeRequest();

  if (res.status === 401 && retryOn401) {
    await bootstrapSession();
    res = await makeRequest();
  }

  return res;
}

async function loadEntryPoint(updateOutput = true) {
  try {
    const res = await authorizedFetch(`/api/entrypoint/${ENTRY_POINT_ID}`);
    const data = await readJsonResponse(res);

    if (!res.ok) {
      renderDebugInfo({
        loadHttpStatus: res.status,
        loadError: data
      });
      throw new Error(data.error || "Load failed");
    }

    const toggle = document.getElementById("emergencyToggle");
    const promptInput = document.getElementById("prompt");

    const emergencyCase =
      typeof data.emergencyCase === "boolean" ? data.emergencyCase : false;
    const emergencyPrompt =
      typeof data.emergencyPrompt === "string" ? data.emergencyPrompt : "";

    toggle.checked = emergencyCase;
    updateLabel();

    const isTypingInPrompt = document.activeElement === promptInput;
    if (!isTypingInPrompt) {
      promptInput.value = emergencyPrompt;
    }

    if (updateOutput) {
      renderDebugInfo({
        entryPointResponse: data
      });
    }
  } catch (err) {
    renderDebugInfo({
      loadException: err.message
    });
  }
}

function updateLabel() {
  const state = document.getElementById("emergencyToggle").checked;
  document.getElementById("stateLabel").innerText = state ? "ON" : "OFF";
}

async function saveState(statusText) {
  const EmergencyCase = document.getElementById("emergencyToggle").checked;
  const EmergencyPrompt = document.getElementById("prompt").value;

  try {
    isUpdating = true;

    renderDebugInfo({
      status: statusText,
      pendingPayload: {
        EmergencyCase,
        EmergencyPrompt
      }
    });

    const res = await authorizedFetch(`/api/entrypoint/${ENTRY_POINT_ID}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ EmergencyCase, EmergencyPrompt })
    });

    const data = await readJsonResponse(res);

    if (!res.ok) {
      renderDebugInfo({
        updateHttpStatus: res.status,
        updateError: data,
        attemptedPayload: {
          EmergencyCase,
          EmergencyPrompt
        }
      });
      throw new Error(data.error || "Update failed");
    }

    renderDebugInfo({
      updateResponse: data
    });

    await loadEntryPoint(false);
  } catch (err) {
    renderDebugInfo({
      updateException: err.message,
      attemptedPayload: {
        EmergencyCase,
        EmergencyPrompt
      }
    });
  } finally {
    isUpdating = false;
  }
}

function startPolling() {
  if (pollHandle) {
    clearInterval(pollHandle);
  }

  pollHandle = setInterval(async () => {
    if (isUpdating || isBootstrapping) return;
    await loadEntryPoint(false);
  }, POLL_INTERVAL_MS);
}

window.toggleEmergency = async function () {
  updateLabel();
  await saveState("Updating toggle...");
};

window.updatePrompt = async function () {
  await saveState("Saving prompt...");
};

window.onload = async function () {
  try {
    await bootstrapSession();
    await loadEntryPoint(true);
    startPolling();
  } catch (err) {
    renderDebugInfo({
      initError: err.message
    });
  }
};

window.onbeforeunload = function () {
  if (pollHandle) {
    clearInterval(pollHandle);
  }
};
