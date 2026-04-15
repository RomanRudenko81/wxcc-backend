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

// =========================
// 🧠 TOKEN STORE
// =========================
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
      const data = fs.readFileSync(TOKEN_FILE);
      tokenStore = JSON.parse(data);
      console.log("🔁 Token aus Datei geladen");
    }
  } catch (err) {
    console.error("❌ Fehler beim Laden des Tokens:", err);
  }
}

// =========================
// 💾 SAVE TOKEN
// =========================
function saveToken() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenStore, null, 2));
    console.log("💾 Token gespeichert");
  } catch (err) {
    console.error("❌ Fehler beim Speichern:", err);
  }
}

// Beim Start laden
loadToken();

// =========================
// 🔐 LOGIN
// =========================
app.get("/login", (req, res) => {
  const scope = encodeURIComponent("cjp:config_read cjp:config_write");

  const url = `https://webexapis.com/v1/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=${scope}`;

  res.redirect(url);
});

// =========================
// 🔁 CALLBACK
// =========================
app.get("/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.send("❌ Kein Code erhalten");
  }

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

    const data = await response.json();

    console.log("🔍 TOKEN RESPONSE:", data);

    if (!data.access_token) {
      return res.send("❌ Token Fehler: " + JSON.stringify(data));
    }

    tokenStore = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000
    };

    saveToken();

    res.send("✅ Login erfolgreich & gespeichert!");

  } catch (err) {
    console.error(err);
    res.send("❌ Fehler beim Token holen");
  }
});

// =========================
// 🔄 REFRESH TOKEN
// =========================
async function refreshAccessToken() {
  console.log("🔄 Refreshing token...");

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

  const data = await response.json();

  console.log("🔍 REFRESH RESPONSE:", data);

  if (!data.access_token) {
    throw new Error("Refresh failed: " + JSON.stringify(data));
  }

  tokenStore = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: Date.now() + data.expires_in * 1000
  };

  saveToken();

  return tokenStore.access_token;
}

// =========================
// 🧠 VALID TOKEN
// =========================
async function getValidToken() {
  if (!tokenStore.access_token) {
    throw new Error("Nicht eingeloggt → /login");
  }

  const now = Date.now();

  if (now >= tokenStore.expires_at - 60000) {
    return await refreshAccessToken();
  }

  return tokenStore.access_token;
}

// =========================
// DEBUG
// =========================
app.get("/debug/token", (req, res) => {
  res.json({
    status: tokenStore.access_token ? "✅ vorhanden" : "❌ fehlt",
    expires_in: tokenStore.expires_at
      ? Math.floor((tokenStore.expires_at - Date.now()) / 1000)
      : null
  });
});

// =========================
// ENTRYPOINT GET
// =========================
app.get("/entrypoint/:id", async (req, res) => {
  try {
    const token = await getValidToken();

    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${req.params.id}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    const text = await response.text();

    console.log("STATUS:", response.status);
    console.log("BODY:", text);

    res.status(response.status).send(text);

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
