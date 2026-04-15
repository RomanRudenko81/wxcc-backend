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
  console.log("===== LOGIN DEBUG =====");
  console.log("CLIENT_ID exists:", !!CLIENT_ID);
  console.log("REDIRECT_URI:", REDIRECT_URI);
  console.log("=======================");

  if (!CLIENT_ID || !REDIRECT_URI) {
    return res.status(500).send(`
      ❌ ENV ERROR

      CLIENT_ID: ${CLIENT_ID}
      REDIRECT_URI: ${REDIRECT_URI}
    `);
  }

  const url = `https://webexapis.com/v1/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=cjp:config cjp:config_write cjp:config_read cjp:user spark:people_read cjds:admin_org_read cjds:admin_org_write cloud-contact-center:pod_conv cjp:task_write cjp:task_read applications_token`;

  console.log("➡️ Redirect URL:", url);

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
    refresh_token: data.refresh_token,
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
// 🆕 DEBUG TOKEN STATUS
// =========================
app.get("/debug/token", (req, res) => {
  res.json({
    status: tokenStore.access_token ? "✅ Token vorhanden" : "❌ kein Token gespeichert",
    access_token_exists: !!tokenStore.access_token,
    refresh_token_exists: !!tokenStore.refresh_token,
    expires_at: tokenStore.expires_at,
    expires_in_seconds: tokenStore.expires_at
      ? Math.floor((tokenStore.expires_at - Date.now()) / 1000)
      : null
  });
});

// =========================
// 🆕 DEBUG AUTH
// =========================
app.get("/debug/auth", async (req, res) => {
  try {
    const token = await getValidToken();

    res.json({
      status: "Token OK",
      token_preview: token?.substring(0, 25)
    });

  } catch (err) {
    res.json({
      status: "ERROR",
      error: err.message
    });
  }
});

// =========================
// 🔥🔥 HARD DIAGNOSIS ENTRYPOINT
// =========================
app.get("/entrypoint/:id", async (req, res) => {
  try {
    console.log("===================================");
    console.log("🔥 ENTRYPOINT HARD DIAGNOSIS START");
    console.log("===================================");

    const token = await getValidToken();

    console.log("TOKEN TYPE:", typeof token);
    console.log("TOKEN VALUE:", token);
    console.log("TOKEN LENGTH:", token?.length);

    if (!token || typeof token !== "string") {
      console.log("❌ TOKEN INVALID DETECTED");

      return res.status(500).json({
        error: "TOKEN INVALID",
        token_type: typeof token,
        token_value: token
      });
    }

    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${req.params.id}`;

    console.log("CALL URL:", url);

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });

    const text = await response.text();

    console.log("RESPONSE STATUS:", response.status);
    console.log("RESPONSE BODY:", text);

    console.log("===================================");
    console.log("🔥 ENTRYPOINT HARD DIAGNOSIS END");
    console.log("===================================");

    return res.status(response.status).send(text);

  } catch (err) {
    console.error("🔥 FATAL ENTRYPOINT ERROR:", err);

    res.status(500).json({
      error: err.message,
      stack: err.stack
    });
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
// HEALTH CHECK
// =========================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "wxcc-backend"
  });
});

// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 WXCC Backend running on port ${PORT}`);
});
