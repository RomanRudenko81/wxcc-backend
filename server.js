import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json());

// 🌍 Webex (EU2 bleibt gleich!)
const BASE_URL = "https://api.wxcc-eu2.cisco.com";
const ORG_ID = "c2e0792b-e4ea-4025-b456-7edc6d1c92cb";

// 🔐 ENV
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// =========================
// 🧠 TOKEN STORE (temporär)
// =========================
let tokenStore = {
  access_token: null,
  refresh_token: null,
  expires_at: null
};

// =========================
// 🔐 LOGIN START
// =========================
app.get("/login", (req, res) => {
  const url = `https://webexapis.com/v1/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=spark:all`;

  res.redirect(url);
});

// =========================
// 🔁 CALLBACK (CODE → TOKEN)
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
        code: code,
        redirect_uri: REDIRECT_URI
      })
    });

    const data = await response.json();

    tokenStore = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000
    };

    console.log("✅ Token gespeichert");

    res.send("✅ Login erfolgreich! Token gespeichert.");
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

  tokenStore = {
    access_token: data.access_token,
    refresh_token: data.refresh_token, // ⚠️ Rotation!
    expires_at: Date.now() + data.expires_in * 1000
  };

  console.log("✅ Token refreshed");

  return tokenStore.access_token;
}

// =========================
// 🧠 VALID TOKEN HOLEN
// =========================
async function getValidToken() {
  if (!tokenStore.access_token) {
    throw new Error("Nicht eingeloggt → /login aufrufen");
  }

  const now = Date.now();

  if (now >= tokenStore.expires_at - 60000) {
    return await refreshAccessToken();
  }

  return tokenStore.access_token;
}

// =========================
// 🆕 DEBUG TOKEN ROUTE (NEU)
// =========================
app.get("/debug/token", (req, res) => {
  if (!tokenStore.access_token) {
    return res.json({
      status: "❌ kein Token gespeichert",
      tokenStore: tokenStore
    });
  }

  res.json({
    status: "✅ Token vorhanden",
    access_token_exists: !!tokenStore.access_token,
    refresh_token_exists: !!tokenStore.refresh_token,
    expires_at: tokenStore.expires_at,
    expires_in_seconds: Math.floor((tokenStore.expires_at - Date.now()) / 1000)
  });
});

// =========================
// HEALTH CHECK
// =========================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "wxcc-backend"
  });
});

// =========================
// GET ENTRY POINT
// =========================
app.get("/entrypoint/:id", async (req, res) => {
  try {
    const token = await getValidToken();

    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${req.params.id}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });

    if (response.status === 401) {
      const newToken = await refreshAccessToken();

      const retry = await fetch(url, {
        headers: {
          Authorization: `Bearer ${newToken}`,
          "Content-Type": "application/json"
        }
      });

      const data = await retry.json();
      return res.json(data);
    }

    const data = await response.json();
    res.json(data);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// PUT ENTRY POINT
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

    const entryPoint = await getRes.json();

    entryPoint.flowOverrideSettings = [
      {
        name: "EmergencyCase",
        type: "BOOLEAN",
        value: req.body.EmergencyCase ? "true" : "false"
      },
      {
        name: "EmergencyPrompt",
        type: "STRING",
        value: req.body.EmergencyPrompt?.trim() || ""
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

    const data = await putRes.json();
    res.json(data);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 WXCC Backend running on port ${PORT}`);
});
