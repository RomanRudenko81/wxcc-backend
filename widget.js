const API_URL = "https://wxcc-backend.onrender.com";
const ENTRY_POINT_ID = "284cd09a-eef4-40a2-82c6-53d08705e3e3";
const POLL_INTERVAL_MS = 5000;

let sessionToken = null;
let currentRole = "viewer";
let isUpdating = false;
let pollHandle = null;

/**
 * Replace this with the exact Webex Desktop SDK identity lookup available
 * in your tenant. This fallback reads query parameters:
 *   ?userId=...&email=...&teamId=...&displayName=...
 */
async function resolveDesktopIdentity() {
  const params = new URLSearchParams(window.location.search);

  return {
    email: params.get("email") || "",
    userId: params.get("userId") || "",
    teamId: params.get("teamId") || "",
    displayName: params.get("displayName") || ""
  };
}

async function bootstrapSession() {
  const identity = await resolveDesktopIdentity();

  const res = await fetch(`${API_URL}/api/session/bootstrap`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(identity)
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || "Session bootstrap failed");
  }

  sessionToken = data.sessionToken;
  currentRole = data.role || "viewer";

  document.getElementById("userInfo").textContent =
    `${data.user?.displayName || "Unknown"}${data.user?.email ? " (" + data.user.email + ")" : ""}`;
  document.getElementById("roleBadge").textContent = currentRole.toUpperCase();

  applyRoleState();
}

function applyRoleState() {
  const writable = currentRole === "supervisor" || currentRole === "admin";

  document.getElementById("emergencyToggle").disabled = !writable;
  document.getElementById("prompt").disabled = !writable;
  document.getElementById("saveBtn").disabled = !writable;
}

window.onload = async function () {
  try {
    await bootstrapSession();
    await loadEntryPoint(true);
    startPolling();
  } catch (err) {
    document.getElementById("output").textContent = "Init error: " + err.message;
  }
};

window.onbeforeunload = function () {
  if (pollHandle) {
    clearInterval(pollHandle);
  }
};

function startPolling() {
  if (pollHandle) {
    clearInterval(pollHandle);
  }

  pollHandle = setInterval(async () => {
    if (isUpdating) return;
    await loadEntryPoint(false);
  }, POLL_INTERVAL_MS);
}

async function apiFetch(path, options = {}) {
  const headers = {
    ...(options.headers || {}),
    Authorization: `Bearer ${sessionToken}`
  };

  return fetch(`${API_URL}${path}`, { ...options, headers });
}

async function loadEntryPoint(updateOutput = true) {
  try {
    const res = await apiFetch(`/api/entrypoint/${ENTRY_POINT_ID}`);
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Load failed");
    }

    const toggle = document.getElementById("emergencyToggle");
    const promptInput = document.getElementById("prompt");

    const emergencyCase = typeof data.emergencyCase === "boolean" ? data.emergencyCase : false;
    const emergencyPrompt = typeof data.emergencyPrompt === "string" ? data.emergencyPrompt : "";

    toggle.checked = emergencyCase;
    updateLabel();

    const isTypingInPrompt = document.activeElement === promptInput;
    if (!isTypingInPrompt) {
      promptInput.value = emergencyPrompt;
    }

    if (updateOutput) {
      document.getElementById("output").textContent = JSON.stringify(data, null, 2);
    }
  } catch (err) {
    document.getElementById("output").textContent = "Load error: " + err.message;
  }
}

function updateLabel() {
  const state = document.getElementById("emergencyToggle").checked;
  document.getElementById("stateLabel").innerText = state ? "ON" : "OFF";
}

async function toggleEmergency() {
  updateLabel();
  await saveState("Updating toggle...");
}

async function updatePrompt() {
  await saveState("Saving prompt...");
}

async function saveState(statusText) {
  const EmergencyCase = document.getElementById("emergencyToggle").checked;
  const EmergencyPrompt = document.getElementById("prompt").value;

  try {
    isUpdating = true;
    document.getElementById("output").textContent = statusText;

    const res = await apiFetch(`/api/entrypoint/${ENTRY_POINT_ID}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ EmergencyCase, EmergencyPrompt })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Update failed");
    }

    document.getElementById("output").textContent = JSON.stringify(data, null, 2);
    await loadEntryPoint(false);
  } catch (err) {
    document.getElementById("output").textContent = "Update error: " + err.message;
  } finally {
    isUpdating = false;
  }
}
