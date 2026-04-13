import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors());
app.use(express.json());

// 🔐 Render Environment Variable
const ACCESS_TOKEN = process.env.WXCC_TOKEN;

// 🌍 Webex API Base
const BASE_URL = "https://api.wxcc-eu2.cisco.com";

/**
 * Health Check (Render benutzt das oft)
 */
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/**
 * Update Entry Point Flow Override
 */
app.put("/entrypoint/:id", async (req, res) => {
  const entryPointId = req.params.id;
  const { EmergencyCase, EmergencyPrompt } = req.body;

  if (!ACCESS_TOKEN) {
    return res.status(500).json({ error: "Missing WXCC_TOKEN" });
  }

  try {
    const response = await fetch(
      `${BASE_URL}/telephony/config/entrypoint/${entryPointId}`,
      {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${ACCESS_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          flowOverrideSettings: {
            EmergencyCase: Boolean(EmergencyCase),
            EmergencyPrompt: EmergencyPrompt || ""
          }
        })
      }
    );

    const data = await response.json();

    res.status(response.status).json(data);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server running");
});