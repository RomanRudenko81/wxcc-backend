import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json());

// 🔐 ENV TOKEN (Render)
const ACCESS_TOKEN = process.env.WXCC_TOKEN;

// 🌍 Webex EU2 Base URL
const BASE_URL = "https://api.wxcc-eu2.cisco.com";

// 🧾 Org ID
const ORG_ID = "c2e0792b-e4ea-4025-b456-7edc6d1c92cb";


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
  const entryPointId = req.params.id;

  if (!ACCESS_TOKEN) {
    return res.status(500).json({
      success: false,
      error: "Missing WXCC_TOKEN in environment"
    });
  }

  try {
    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${entryPointId}`;

    console.log("➡️ GET EntryPoint:", url);

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      }
    });

    const raw = await response.text();

    console.log("⬅️ GET Status:", response.status);

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: "WxCC GET failed",
        raw
      });
    }

    const data = JSON.parse(raw);
    return res.json(data);

  } catch (err) {
    console.error("❌ GET error:", err);

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});


// =========================
// PUT ENTRY POINT (FIXED FULL OBJECT MERGE)
// =========================
app.put("/entrypoint/:id", async (req, res) => {
  const entryPointId = req.params.id;
  const { EmergencyCase, EmergencyPrompt } = req.body;

  if (!ACCESS_TOKEN) {
    return res.status(500).json({
      success: false,
      error: "Missing WXCC_TOKEN in environment"
    });
  }

  try {
    const url = `${BASE_URL}/organization/${ORG_ID}/entry-point/${entryPointId}`;

    console.log("➡️ STEP 1 - GET current EntryPoint");

    // 🔥 STEP 1: GET full object
    const getRes = await fetch(url, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      }
    });

    const entryPoint = await getRes.json();

    console.log("⬅️ Current EntryPoint loaded");

    // 🔥 STEP 2: Modify ONLY flowOverrideSettings
    entryPoint.flowOverrideSettings = [
      {
        name: "EmergencyCase",
        type: "BOOLEAN",
        value: EmergencyCase ? "true" : "false"
      },
      {
        name: "EmergencyPrompt",
        type: "STRING",
        value: EmergencyPrompt?.trim() || ""
      }
    ];

    console.log("📦 FINAL PAYLOAD:");
    console.log(JSON.stringify(entryPoint, null, 2));

    // 🔥 STEP 3: PUT FULL OBJECT BACK
    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(entryPoint)
    });

    const raw = await response.text();

    console.log("⬅️ PUT Status:", response.status);
    console.log("⬅️ PUT Raw:", raw);

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: "WxCC update failed",
        status: response.status,
        raw
      });
    }

    return res.json({
      success: true,
      status: response.status,
      data: JSON.parse(raw)
    });

  } catch (err) {
    console.error("❌ PUT error:", err);

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});


// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 WXCC Backend running on port ${PORT}`);
});
