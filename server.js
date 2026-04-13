import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json());

// 🔐 ENV TOKEN (Render)
const ACCESS_TOKEN = process.env.WXCC_TOKEN;

// 🌍 Webex EU2 Base URL (wichtig!)
const BASE_URL = "https://api.wxcc-eu2.cisco.com";

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
// ENTRY POINT UPDATE
// =========================
app.put("/entrypoint/:id", async (req, res) => {
  const entryPointId = req.params.id;
  const { EmergencyCase, EmergencyPrompt } = req.body;

  console.log("➡️ Incoming request");
  console.log("EntryPoint ID:", entryPointId);
  console.log("Body:", req.body);

  if (!ACCESS_TOKEN) {
    return res.status(500).json({
      success: false,
      error: "Missing WXCC_TOKEN in environment"
    });
  }

  try {
    const url = `${BASE_URL}/organization/c2e0792b-e4ea-4025-b456-7edc6d1c92cb/entry-point/${entryPointId}`;

    console.log("➡️ Calling Webex API:", url);

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        flowOverrideSettings: {
          EmergencyCase: !!EmergencyCase,
          EmergencyPrompt: EmergencyPrompt || ""
        }
      })
    });

    const raw = await response.text();

    console.log("⬅️ Webex Status:", response.status);
    console.log("⬅️ Webex Raw Response:", raw);

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = { raw };
    }

    return res.status(response.status).json({
      success: response.ok,
      status: response.status,
      data: parsed
    });

  } catch (err) {
    console.error("❌ Backend error:", err);

    return res.status(500).json({
      success: false,
      error: "Backend exception",
      message: err.message
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
