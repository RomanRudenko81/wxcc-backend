import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import fs from "fs";

const app = express();

app.use(cors());
app.use(express.json());

// 🌍 Webex
const BASE_URL = "https://api.wxcc-eu2.cisco.com";
const ORG_ID = "c2e0792b-e4ea-4025-b456-7edc6d1c92cb";

// 🔐 ENV
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// 📁 Token File
const TOKEN_FILE = "token.json";

let tokenStore = {
  access_token: null,
  refresh_token: null,
  expires_at: null
};

// =========================
// 💾 LOAD TOKEN
// =========================
function loadToken() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = fs.readFileSync(TOKEN_FILE, "utf-8");
      tokenStore = JSON.parse(data);
      console.log("🔁 Token geladen");
    }
  } catch (err) {
    console.error("❌ Token load error:", err);
  }
}

// =========================
// 💾 SAVE TOKEN
// =========================
function saveToken() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenStore, null, 2));
  } catch (err) {
    console.error("❌ Token save error:", err);
  }
}

loadToken();

// =========================
// 🧠 SAFE JSON HELPER
// =========================
async function safeJson(response) {
  const text = await response.text();

  console.log("RESPONSE STATUS:", response.status);
  console.log("RESPONSE BODY:", text);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${text}`);
  }

  if (text.trim().startsWith("<")) {
    throw new Error("HTML statt JSON erhalten: " + text);
  }

  return JSON.parse(text);
}

// =========================
// LOGIN
// =========================
app.get("/login", (req, res) => {
  const scope = encodeURIComponent("cjp:config_read cjp:config_write");

  const url = `https://webexapis.com/v1/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=${scope}`;

  res.redirect(url);
});

// =========================
// CALLBACK
// =========================
app.get("/callback", async (req, res) => {
  const code = req.query.code;

  try {
    const response = await fetch("https://webexapis.com/v1/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI
      })
    });

    const data = await safeJson(response);

    tokenStore = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000
    };

    saveToken();
    res.send("✅ Login OK");

  } catch (err) {
    res.status(500).send(err.message);
  }
});

// =========================
// REFRESH TOKEN
// =========================
async function refreshAccessToken() {
  const response = await fetch("https://webexapis.com/v1/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: tokenStore.refresh_token
    })
  });

  const data = await safeJson(response);

  tokenStore = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: Date.now() + data.expires_in * 1000
  };

  saveToken();
  return tokenStore.access_token;
}

// =========================
// GET VALID TOKEN
// =========================
async function getValidToken() {
  if (!tokenStore.access_token) {
    throw new Error("Not logged in");
  }

  const now = Date.now();

  if (now >= tokenStore.expires_at - 60000) {
    return await refreshAccessToken();
  }

  return tokenStore.access_token;
}

// =========================
// ENTRYPOINT GET (NORMALIZED)
// =========================
app.get("/entrypoint/:id", async (req, res) => {
  try {
    const token = await getValidToken();

    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${req.params.id}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      }
    });

    const text = await response.text();

    if (text.trim().startsWith("<")) {
      return res.status(500).json({
        error: "API returned HTML instead of JSON",
        raw: text
      });
    }

    const data = JSON.parse(text);

    const overrides = data.flowOverrideSettings || [];

    const emergencyCase = overrides.find(o => o.name === "EmergencyCase");
    const emergencyPrompt = overrides.find(o => o.name === "EmergencyPrompt");

    res.json({
      ...data,
      flowOverrideSettings: overrides,
      emergencyCase: emergencyCase?.value === "true",
      emergencyPrompt: emergencyPrompt?.value || ""
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// PUT ENTRYPOINT
// =========================
app.put("/entrypoint/:id", async (req, res) => {
  try {
    const token = await getValidToken();

    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${req.params.id}`;

    const getRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    const entryPoint = await safeJson(getRes);

    entryPoint.flowOverrideSettings = [
      {
        name: "EmergencyCase",
        type: "BOOLEAN",
        value: req.body.EmergencyCase ? "true" : "false"
      },
      {
        name: "EmergencyPrompt",
        type: "STRING",
        value: String(req.body.EmergencyPrompt || "").trim()
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

// =========================
// START
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
});
