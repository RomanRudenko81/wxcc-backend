import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json());

// 🔐 ENV VAR (Render Secret)
const ACCESS_TOKEN = process.env.WXCC_TOKEN;

// 🌍 Webex Base URL
const BASE_URL = "https://api.wxcc-us1.cisco.com";

/* =========================
   HEALTH CHECK
========================= */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "wxcc-backend"
  });
});

/* =========================
   ENTRY POINT UPDATE
========================= */
app.put("/entrypoint/:id", async (req, res) => {
  const entryPointId = req.params.id;

  const { EmergencyCase, EmergencyPrompt } = req.body;

  if (!ACCESS_TOKEN) {
    return res.status(500).json({
      error: "Missing WXCC_TOKEN in environment"
    });
  }

  try {
    const response = await fetch(
      `${BASE_URL}/organization/c2e0792b-e4ea-4025-b456-7edc6d1c92cb/entry-point/${entryPointId}`,
      {
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
      }
    );

    /* =========================
       SAFE RESPONSE HANDLING
    ========================= */

    const contentType = response.headers.get("content-type");

    let data;

    // 🔥 case 1: JSON response
    if (contentType && contentType.includes("application/json")) {
      data = await response.json().catch(() => null);
    } else {
      // 🔥 case 2: text / empty / html
      const text = await response.text().catch(() => "");
      data = { raw: text };
    }

    /* =========================
       RETURN CLEAN RESPONSE
    ========================= */

    return res.status(response.status).json({
      success: response.ok,
      status: response.status,
      data
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Backend exception",
      message: err.message
    });
  }
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 WXCC Backend running on port ${PORT}`);
});
