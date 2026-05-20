const FRONTEND_BUILD_ID = "wxcc-widget-subscription-cleanup-full-2026-05-20-v27";
class SupervisorAccessWidget extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });

    this.API_URL = "https://wxcc-backend.onrender.com";
    this.ENTRY_POINT_ID = "284cd09a-eef4-40a2-82c6-53d08705e3e3";

    this.POLL_INTERVAL_MS = 5000;
    this.WALLBOARD_POLL_INTERVAL_MS = 5000;

    this.sessionToken = null;
    this.currentRole = "viewer";
    this.isUpdating = false;
    this.isBootstrapping = false;
    this.pollHandle = null;
    this.wallboardPollHandle = null;
    this.wallboardEventSource = null;
    this.wallboardReconnectHandle = null;
    this.wallboardWatchdogHandle = null;
    this.wallboardLastDataTs = 0;
    this.wallboardLastEventTs = 0;
    this.wallboardManualRefreshInFlight = false;
    this.wallboardLastManualRefreshTs = 0;
    this.historyConnectedMismatchSinceTs = 0;
    this.historyConnectedMismatchLastRefreshTs = 0;
    this.focusResumeRefreshHandle = null;
    this.focusResumeLastRefreshTs = 0;
    this.boundFocusResumeRefresh = null;
    this.sseClientDebugEvents = [];
    this.sseClientDebugMax = 120;
    this.widgetWatchdogCounters = {};
    this.widgetLastSignature = "";
    this.widgetLastSignatureTs = 0;
    this.widgetAnomalySince = {};
    this.activeCallTimerHandle = null;
    this.lastWallboardData = null;
    this.activeCallRenderCache = new Map();
    this.callHistoryRenderCache = [];
    this.callHistoryCacheTs = 0;
    this.hasUnsavedChanges = false;
    this.themeMode = localStorage.getItem("supervisorWidgetTheme") || "dark";
    this.allowedQueueNames = [];
    this.selectedQueueFilters = this.readSelectedQueueFilters();
  }

  connectedCallback() {
    this.render();
    this.applyTheme();
    this.populateStaticOptions();
    this.bindEvents();
    this.init();
    this.startWallboardWatchdog();
    this.bindFocusResumeRefresh();
    this.startRobustActiveCallTimer();
  }

  disconnectedCallback() {
    if (this.pollHandle) clearInterval(this.pollHandle);
    if (this.wallboardPollHandle) clearInterval(this.wallboardPollHandle);
    if (this.wallboardReconnectHandle) clearTimeout(this.wallboardReconnectHandle);
    if (this.wallboardWatchdogHandle) clearInterval(this.wallboardWatchdogHandle);
    if (this.activeCallTimerHandle) clearInterval(this.activeCallTimerHandle);
    if (this.focusResumeRefreshHandle) clearTimeout(this.focusResumeRefreshHandle);
    this.removeFocusResumeRefresh();
    if (this.wallboardEventSource) this.wallboardEventSource.close();
  }

  readSelectedQueueFilters() {
    try {
      const raw = localStorage.getItem("supervisorWidgetSelectedQueues");
      const parsed = JSON.parse(raw || "[]");
      return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
    } catch {
      return [];
    }
  }

  saveSelectedQueueFilters() {
    try {
      localStorage.setItem(
        "supervisorWidgetSelectedQueues",
        JSON.stringify(Array.isArray(this.selectedQueueFilters) ? this.selectedQueueFilters : [])
      );
    } catch {
      // Ignore storage issues inside embedded desktop.
    }
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          all: initial;
          display: block;
          width: 100%;
          min-height: 100%;
          box-sizing: border-box;
          font-family: Arial, Helvetica, sans-serif !important;

          --card: rgba(255,255,255,0.90);
          --cardBorder: rgba(0,0,0,0.10);
          --panelBorder: rgba(0,0,0,0.30);
          --input: rgba(255,255,255,0.95);
          --inputBorder: rgba(0,0,0,0.18);
          --text: #111827;
          --muted: rgba(17,24,39,0.72);
          --kpi: rgba(0,0,0,0.08);
          --switch: #9ca3af;
          --button: #0a84ff;
          --tableBorder: rgba(0,0,0,0.10);

          color: var(--text);
        }

        :host(.theme-dark) {
          --card: rgba(15, 23, 42, 0.82);
          --cardBorder: rgba(255,255,255,0.08);
          --panelBorder: rgba(255,255,255,0.28);
          --input: rgba(255,255,255,0.10);
          --inputBorder: rgba(255,255,255,0.14);
          --text: #ffffff;
          --muted: rgba(255,255,255,0.75);
          --kpi: rgba(255,255,255,0.14);
          --switch: #4b5563;
          --button: #0a84ff;
          --tableBorder: rgba(255,255,255,0.08);
        }

        :host *,
        :host *::before,
        :host *::after {
          box-sizing: border-box !important;
          font-family: Arial, Helvetica, sans-serif !important;
          text-transform: none !important;
          font-variant: normal !important;
          font-variant-caps: normal !important;
          font-feature-settings: normal !important;
          letter-spacing: normal !important;
        }

        .wrapper {
          width: 100%;
          height: 100vh;
          overflow-y: auto;
          overflow-x: hidden;
          padding: 22px;
          color: var(--text);
          scrollbar-width: thin;
          scrollbar-color: rgba(255,255,255,0.35) rgba(255,255,255,0.08);
        }

        .wrapper::-webkit-scrollbar {
          width: 8px;
        }

        .wrapper::-webkit-scrollbar-track {
          background: rgba(255,255,255,0.06);
          border-radius: 999px;
        }

        .wrapper::-webkit-scrollbar-thumb {
          background: rgba(255,255,255,0.35);
          border-radius: 999px;
        }

        .wrapper::-webkit-scrollbar-thumb:hover {
          background: rgba(255,255,255,0.50);
        }

        :host(.theme-light) .wrapper {
          scrollbar-color: rgba(0,0,0,0.35) rgba(0,0,0,0.08);
        }

        :host(.theme-light) .wrapper::-webkit-scrollbar-track {
          background: rgba(0,0,0,0.06);
        }

        :host(.theme-light) .wrapper::-webkit-scrollbar-thumb {
          background: rgba(0,0,0,0.35);
        }

        :host(.theme-light) .wrapper::-webkit-scrollbar-thumb:hover {
          background: rgba(0,0,0,0.50);
        }

        .card {
          width: 100%;
          border-radius: 18px;
          background: var(--card);
          border: 1px solid var(--cardBorder);
          padding: 28px;
          backdrop-filter: blur(10px);
          -webkit-backdrop-filter: blur(10px);
          color: var(--text);
        }

        .header {
          display: flex;
          justify-content: space-between;
          gap: 30px;
          margin-bottom: 30px;
        }

        .title {
          font-size: 28px;
          font-weight: 700;
          margin: 0;
          color: var(--text);
          line-height: 1.2;
        }

        .subtitle {
          margin-top: 8px;
          font-size: 13px;
          color: var(--muted);
        }

        .badge-row {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-top: 12px;
          justify-content: flex-end;
        }

        .badge,
        .theme-btn {
          background: var(--kpi);
          border-radius: 999px;
          padding: 6px 12px;
          font-size: 12px;
          color: var(--text);
          border: 1px solid var(--cardBorder);
        }

        .theme-btn {
          cursor: pointer;
        }

        .toggle-row {
          display: flex;
          align-items: center;
          gap: 14px;
          margin-bottom: 28px;
          font-size: 14px;
          color: var(--text);
        }

        .switch {
          position: relative;
          width: 52px;
          height: 28px;
          display: inline-block;
          flex: 0 0 auto;
        }

        .switch input {
          opacity: 0;
          width: 0;
          height: 0;
        }

        .slider {
          position: absolute;
          inset: 0;
          cursor: pointer;
          background: var(--switch);
          border-radius: 999px;
          transition: .25s;
        }

        .slider:before {
          position: absolute;
          content: "";
          height: 20px;
          width: 20px;
          left: 4px;
          top: 4px;
          background: white;
          border-radius: 50%;
          transition: .25s;
        }

        input:checked + .slider {
          background: #22c55e;
        }

        input:checked + .slider:before {
          transform: translateX(24px);
        }


        .config-toggle {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin: 10px 0 18px 0;
          padding: 12px 16px;
          border-radius: 12px;
          background: var(--kpi);
          border: 1px solid var(--cardBorder);
          cursor: pointer;
          user-select: none;
        }

        .config-toggle-title {
          font-size: 14px;
          font-weight: 600;
          color: var(--text);
        }

        .config-toggle-icon {
          transition: transform 0.25s ease;
          color: var(--text);
        }

        .config-toggle.collapsed .config-toggle-icon {
          transform: rotate(-90deg);
        }

        .config-content {
          overflow: hidden;
          transition: max-height 0.35s ease, opacity 0.25s ease;
          max-height: 1200px;
          opacity: 1;
        }

        .config-content.collapsed {
          max-height: 0;
          opacity: 0;
          pointer-events: none;
        }

        .kpi.calls-in-queue-card {
          position: relative;
          overflow: visible;
        }

        .kpi-topline {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 10px;
        }

        .queue-filter-inline {
          position: relative;
          display: none;
          flex: 0 0 auto;
        }

        .queue-filter-inline.visible {
          display: block;
        }

        .queue-filter-button {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          min-height: 24px;
          max-width: 150px;
          padding: 4px 8px;
          border-radius: 999px;
          border: 1px solid var(--cardBorder);
          background: rgba(255,255,255,0.10);
          color: var(--text) !important;
          font-size: 11px;
          line-height: 1;
          cursor: pointer;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        :host(.theme-light) .queue-filter-button {
          background: rgba(0,0,0,0.06);
        }

        .queue-filter-menu {
          position: absolute;
          top: 30px;
          right: 0;
          z-index: 50;
          display: none;
          min-width: 210px;
          padding: 10px;
          border-radius: 12px;
          border: 1px solid var(--cardBorder);
          background: var(--card);
          box-shadow: 0 12px 30px rgba(0,0,0,0.35);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
        }

        .queue-filter-inline.open .queue-filter-menu {
          display: block;
        }

        .queue-filter-option {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 7px 4px;
          color: var(--text);
          font-size: 12px;
          cursor: pointer;
        }

        .queue-filter-option input {
          width: auto;
          margin: 0;
        }

        .queue-filter-hint {
          margin-top: 6px;
          padding-top: 8px;
          border-top: 1px solid var(--tableBorder);
          color: var(--muted);
          font-size: 11px;
          line-height: 1.3;
        }

        .section-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0,1fr));
          gap: 42px;
        }

        .section-title,
        .dashboard-title,
        .agents-title,
        .calls-title {
          font-size: 22px;
          font-weight: 700;
          margin: 0 0 18px 0;
          color: var(--text);
          line-height: 1.25;
        }

        .field {
          margin-bottom: 18px;
        }

        .field label {
          display: block;
          font-size: 13px;
          margin-bottom: 8px;
          color: var(--muted);
        }

        input[type="text"],
        select {
          width: 100%;
          padding: 14px;
          border-radius: 12px;
          border: 1px solid var(--inputBorder);
          background: var(--input);
          color: var(--text) !important;
          outline: none;
          font-size: 14px;
        }

        input[type="text"]::placeholder {
          color: var(--muted);
        }

        button {
          background: var(--button);
          color: white !important;
          border: none;
          border-radius: 10px;
          padding: 10px 16px;
          cursor: pointer;
          font-size: 14px;
        }

        button[disabled],
        input[disabled],
        select[disabled] {
          opacity: 0.55;
          cursor: not-allowed;
        }

        .status {
          margin-top: 14px;
          font-size: 13px;
          color: var(--muted);
          min-height: 18px;
        }

        .dashboard {
          margin-top: 34px;
        }

        .kpis {
          display: grid;
          grid-template-columns: repeat(7, minmax(0,1fr));
          gap: 12px;
        }

        .kpi {
          background: var(--kpi);
          border: 1px solid transparent;
          border-radius: 14px;
          padding: 14px;
          min-height: 74px;
          transition: background .25s ease, border-color .25s ease, box-shadow .25s ease;
        }

        .kpi-green {
          background: linear-gradient(135deg, rgba(34,197,94,0.22), rgba(34,197,94,0.10));
          border-color: rgba(34,197,94,0.72);
          box-shadow: 0 0 0 1px rgba(34,197,94,0.10), 0 0 18px rgba(34,197,94,0.16);
        }

        .kpi-orange {
          background: linear-gradient(135deg, rgba(245,158,11,0.24), rgba(245,158,11,0.10));
          border-color: rgba(245,158,11,0.78);
          box-shadow: 0 0 0 1px rgba(245,158,11,0.10), 0 0 18px rgba(245,158,11,0.16);
        }

        .kpi-red,
        .kpi-critical {
          background: linear-gradient(135deg, rgba(239,68,68,0.24), rgba(239,68,68,0.10));
          border-color: rgba(239,68,68,0.82);
          box-shadow: 0 0 0 1px rgba(239,68,68,0.12), 0 0 18px rgba(239,68,68,0.18);
        }

        .kpi-critical {
          animation: supervisorCriticalPulse 1.4s ease-in-out infinite;
        }

        @keyframes supervisorCriticalPulse {
          0%, 100% {
            border-color: rgba(239,68,68,0.70);
            box-shadow: 0 0 0 1px rgba(239,68,68,0.10), 0 0 14px rgba(239,68,68,0.16);
          }
          50% {
            border-color: rgba(239,68,68,1);
            box-shadow: 0 0 0 1px rgba(239,68,68,0.26), 0 0 26px rgba(239,68,68,0.42);
          }
        }

        .kpi-label {
          font-size: 13px;
          color: var(--muted);
        }

        .kpi-value {
          font-size: 24px;
          font-weight: 700;
          margin-top: 8px;
          color: var(--text);
        }

        .agents-section {
          margin-top: 28px;
        }

        .table {
          width: 100%;
        }

        .table-row {
          display: grid;
          grid-template-columns: 1.2fr 1fr 1fr 1fr;
          gap: 16px;
          padding: 12px 0;
          border-bottom: 1px solid var(--tableBorder);
          align-items: center;
          color: var(--text);
          font-size: 14px;
          transition: background .25s ease, border-color .25s ease, box-shadow .25s ease;
        }

        .table-row.agent-available,
        .table-row.agent-unavailable {
          border: 1px solid transparent;
          border-radius: 14px;
          padding: 14px;
          margin: 10px 0;
        }

        .table-row.agent-available {
          background: linear-gradient(135deg, rgba(34,197,94,0.18), rgba(34,197,94,0.08));
          border-color: rgba(34,197,94,0.78);
          box-shadow: 0 0 0 1px rgba(34,197,94,0.08), 0 0 18px rgba(34,197,94,0.14);
        }

        .table-row.agent-unavailable {
          background: linear-gradient(135deg, rgba(239,68,68,0.18), rgba(239,68,68,0.08));
          border-color: rgba(239,68,68,0.82);
          box-shadow: 0 0 0 1px rgba(239,68,68,0.08), 0 0 18px rgba(239,68,68,0.14);
        }

        .table-header,
        .call-header {
          color: var(--muted);
          font-weight: 700;
        }

        .calls-wrapper {
          margin-top: 34px;
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 18px;
        }

        .calls-card.call-history-card {
          grid-column: 1 / -1;
        }

        @media (max-width: 1200px) {
          .calls-wrapper {
            grid-template-columns: 1fr;
          }

          .calls-card.call-history-card {
            grid-column: auto;
          }
        }

        .calls-card {
          border: 2px solid var(--panelBorder);
          border-radius: 16px;
          padding: 20px;
          overflow-x: auto;
          min-width: 0;
          background: rgba(255,255,255,0.02);
        }

        .calls-card.collapsible {
          padding: 0;
          overflow: hidden;
        }

        .calls-toggle {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          padding: 16px 20px;
          cursor: pointer;
          user-select: none;
          border-bottom: 1px solid var(--tableBorder);
        }

        .calls-toggle-title {
          font-size: 18px;
          font-weight: 700;
          color: var(--text);
        }

        .calls-toggle-subtitle {
          margin-top: 4px;
          font-size: 12px;
          color: var(--muted);
          font-weight: 500;
        }

        .calls-toggle-icon {
          transition: transform 0.25s ease;
          color: var(--text);
          font-size: 16px;
        }

        .calls-toggle.collapsed .calls-toggle-icon {
          transform: rotate(-90deg);
        }

        .calls-content {
          overflow-x: auto;
          overflow-y: hidden;
          transition: max-height 0.35s ease, opacity 0.25s ease;
          max-height: 900px;
          opacity: 1;
          padding: 0 20px 20px 20px;
        }

        .calls-content.collapsed {
          max-height: 0;
          opacity: 0;
          pointer-events: none;
          padding-bottom: 0;
        }

        :host(.theme-light) .calls-card {
          background: rgba(0,0,0,0.02);
        }

        .calls-table {
          min-width: 760px;
        }

        #callHistoryList {
          min-width: 1400px;
        }

        .call-row {
          display: grid;
          grid-template-columns:
            minmax(90px,0.8fr)
            minmax(140px,1fr)
            minmax(160px,1.1fr)
            minmax(180px,1.2fr)
            minmax(90px,0.7fr)
            minmax(90px,0.7fr);
          gap: 14px;
          padding: 12px 0;
          border-bottom: 1px solid var(--tableBorder);
          align-items: center;
          color: var(--text);
          white-space: nowrap;
          font-size: 14px;
        }

        .call-row.active {
          grid-template-columns:
            minmax(90px,0.8fr)
            minmax(140px,1fr)
            minmax(160px,1.1fr)
            minmax(140px,1fr)
            minmax(90px,0.7fr)
            minmax(90px,0.7fr);
        }

        .call-row.history {
          grid-template-columns:
            minmax(90px,0.8fr)
            minmax(140px,1fr)
            minmax(150px,1fr)
            minmax(140px,1fr)
            minmax(180px,1.1fr)
            minmax(140px,0.9fr)
            minmax(110px,0.8fr)
            minmax(100px,0.7fr)
            minmax(90px,0.7fr)
            minmax(160px,1fr);
        }

        #wallboardStatus {
          margin-top: 12px;
          font-size: 13px;
          color: var(--muted);
        }

        @media (max-width: 1400px) {
          .kpis {
            grid-template-columns: repeat(4, minmax(0,1fr));
          }
        }

        @media (max-width: 980px) {
  
        .config-toggle {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin: 10px 0 18px 0;
          padding: 12px 16px;
          border-radius: 12px;
          background: var(--kpi);
          border: 1px solid var(--cardBorder);
          cursor: pointer;
          user-select: none;
        }

        .config-toggle-title {
          font-size: 14px;
          font-weight: 600;
          color: var(--text);
        }

        .config-toggle-icon {
          transition: transform 0.25s ease;
          color: var(--text);
        }

        .config-toggle.collapsed .config-toggle-icon {
          transform: rotate(-90deg);
        }

        .config-content {
          overflow: hidden;
          transition: max-height 0.35s ease, opacity 0.25s ease;
          max-height: 1200px;
          opacity: 1;
        }

        .config-content.collapsed {
          max-height: 0;
          opacity: 0;
          pointer-events: none;
        }

        .kpi.calls-in-queue-card {
          position: relative;
          overflow: visible;
        }

        .kpi-topline {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 10px;
        }

        .queue-filter-inline {
          position: relative;
          display: none;
          flex: 0 0 auto;
        }

        .queue-filter-inline.visible {
          display: block;
        }

        .queue-filter-button {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          min-height: 24px;
          max-width: 150px;
          padding: 4px 8px;
          border-radius: 999px;
          border: 1px solid var(--cardBorder);
          background: rgba(255,255,255,0.10);
          color: var(--text) !important;
          font-size: 11px;
          line-height: 1;
          cursor: pointer;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        :host(.theme-light) .queue-filter-button {
          background: rgba(0,0,0,0.06);
        }

        .queue-filter-menu {
          position: absolute;
          top: 30px;
          right: 0;
          z-index: 50;
          display: none;
          min-width: 210px;
          padding: 10px;
          border-radius: 12px;
          border: 1px solid var(--cardBorder);
          background: var(--card);
          box-shadow: 0 12px 30px rgba(0,0,0,0.35);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
        }

        .queue-filter-inline.open .queue-filter-menu {
          display: block;
        }

        .queue-filter-option {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 7px 4px;
          color: var(--text);
          font-size: 12px;
          cursor: pointer;
        }

        .queue-filter-option input {
          width: auto;
          margin: 0;
        }

        .queue-filter-hint {
          margin-top: 6px;
          padding-top: 8px;
          border-top: 1px solid var(--tableBorder);
          color: var(--muted);
          font-size: 11px;
          line-height: 1.3;
        }

        .section-grid {
            grid-template-columns: 1fr;
          }

          .kpis {
            grid-template-columns: repeat(2, minmax(0,1fr));
          }

          .table-row {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 640px) {
          .wrapper {
            padding: 8px;
          }

          .card {
            padding: 18px;
          }

          .header {
            flex-direction: column;
          }

          .badge-row {
            justify-content: flex-start;
          }

          .kpis {
            grid-template-columns: 1fr;
          }

          .calls-wrapper {
            grid-template-columns: 1fr;
          }
        }
      </style>

      <div class="wrapper">
        <div class="card">
          <div class="header">
            <div>
              <h2 class="title">Supervisor Access Control</h2>
              <div class="subtitle" id="userInfo">Loading...</div>
            </div>

            <div>
              <h2 class="title">Conscia Demo Support</h2>
              <div class="badge-row">
                <button class="theme-btn" id="themeToggleBtn" type="button">Theme: Dark</button>
                <div class="badge" id="roleBadge">...</div>
              </div>
            </div>
          </div>

          <div class="config-toggle" id="configToggle">
            <div class="config-toggle-title">Call flow settings</div>
            <div class="config-toggle-icon">▼</div>
          </div>

          <div class="config-content" id="configContent">
          <div class="toggle-row">
            <label class="switch">
              <input type="checkbox" id="emergencyToggle">
              <span class="slider"></span>
            </label>
            <div>Emergency Mode: <span id="stateLabel">OFF</span></div>
          </div>

          <div class="section-grid">
            <div>
              <div class="section-title">Prompts</div>
              <div class="field">
                <label>Emergency Prompt</label>
                <input id="emergencyPrompt" type="text">
              </div>
              <div class="field">
                <label>Holiday Prompt</label>
                <input id="holidayPrompt" type="text">
              </div>
            </div>

            <div>
              <div class="section-title">Language Settings</div>
              <div class="field">
                <label>Global Language</label>
                <select id="globalLanguage"></select>
              </div>
              <div class="field">
                <label>Global Voice Name</label>
                <select id="globalVoiceName"></select>
              </div>
            </div>

            <div>
              <div class="section-title">Queue Settings</div>
              <div class="field">
                <label>Prio Queue</label>
                <select id="priorityQueue"></select>
              </div>
              <div class="field">
                <label>MoH Sales Queue</label>
                <input id="mohSalesQueue" type="text">
              </div>
            </div>
          </div>

          <div style="margin-top:18px;">
            <button id="saveBtn">Save</button>
          </div>

          <div class="status" id="status">Loading...</div>

          </div>

          <div class="dashboard">
            <div class="dashboard-title">Dashboard</div>

            <div class="kpis">
              <div class="kpi calls-in-queue-card" id="kpiCardCallsInQueue">
                <div class="kpi-topline">
                  <div class="kpi-label">Calls in Queue</div>
                  <div class="queue-filter-inline" id="queueFilterWrapper">
                    <button class="queue-filter-button" id="queueFilterButton" type="button">Queues ▾</button>
                    <div class="queue-filter-menu" id="queueFilterMenu"></div>
                  </div>
                </div>
                <div class="kpi-value" id="kpiCallsInQueue">0</div>
              </div>
              <div class="kpi"><div class="kpi-label">Active Calls</div><div class="kpi-value" id="kpiActiveCalls">0</div></div>
              <div class="kpi"><div class="kpi-label">Longest Waiting</div><div class="kpi-value" id="kpiLongestWaiting">0s</div></div>
              <div class="kpi"><div class="kpi-label">Avg Wait</div><div class="kpi-value" id="kpiAvgWait">0s</div></div>
              <div class="kpi"><div class="kpi-label">Avg Handle</div><div class="kpi-value" id="kpiAvgHandle">0s</div></div>
              <div class="kpi"><div class="kpi-label">Logged-in Agents</div><div class="kpi-value" id="kpiLoggedIn">0</div></div>
              <div class="kpi"><div class="kpi-label">Available Agents</div><div class="kpi-value" id="kpiAvailable">0</div></div>
            </div>
          </div>

          <div class="agents-section">
            <div class="agents-title">Agents</div>
            <div class="table" id="agentList">
              <div class="table-row table-header">
                <div>Name</div><div>Status</div><div>Team</div><div>Active Since</div>
              </div>
            </div>
            <div id="wallboardStatus">Loading dashboard...</div>
          </div>

          <div class="calls-wrapper">
            <div class="calls-card">
              <div class="calls-title">Waiting Calls</div>
              <div class="calls-table" id="waitingCallList">
                <div class="call-row call-header">
                  <div>Status</div><div>Queue</div><div>Caller</div><div>Entry Point</div><div>Waiting</div><div>Task</div>
                </div>
              </div>
            </div>

            <div class="calls-card">
              <div class="calls-title">Active Calls</div>
              <div class="calls-table" id="activeCallList">
                <div class="call-row active call-header">
                  <div>Status</div><div>Queue</div><div>Caller</div><div>Agent</div><div>Handle</div><div>Task</div>
                </div>
              </div>
            </div>

            <div class="calls-card collapsible call-history-card">
              <div class="calls-toggle" id="callHistoryToggle">
                <div>
                  <div class="calls-toggle-title">Call History</div>
                  <div class="calls-toggle-subtitle">Current selected queues · Last 24h</div>
                </div>
                <div class="calls-toggle-icon">▼</div>
              </div>
              <div class="calls-content" id="callHistoryContent">
                <div class="calls-table" id="callHistoryList">
                  <div class="call-row history call-header">
                    <div>Status</div><div>Queue</div><div>Caller</div><div>Agent</div><div>Wrapup Reason</div><div>Handle / Type</div><div>Termination Reason</div><div>Started</div><div>Duration</div><div>Task</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  applyTheme() {
    this.classList.toggle("theme-light", this.themeMode === "light");
    this.classList.toggle("theme-dark", this.themeMode === "dark");

    const btn = this.shadowRoot.getElementById("themeToggleBtn");
    if (btn) {
      btn.textContent = this.themeMode === "dark" ? "Theme: Dark" : "Theme: Light";
    }
  }

  toggleTheme() {
    this.themeMode = this.themeMode === "dark" ? "light" : "dark";
    localStorage.setItem("supervisorWidgetTheme", this.themeMode);
    this.applyTheme();
  }

  populateStaticOptions() {
    this.setSelectOptions(this.$priorityQueue(), Array.from({ length: 10 }, (_, i) => String(i + 1)));
    this.setSelectOptions(this.$globalLanguage(), ["de-DE", "en-US"]);
    this.updateVoiceOptions();
  }

  setSelectOptions(el, values) {
    el.innerHTML = "";
    values.forEach(value => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      el.appendChild(option);
    });
  }

  bindEvents() {
    this.$themeToggleBtn().addEventListener("click", () => this.toggleTheme());

    this.$toggle().addEventListener("change", () => {
      this.hasUnsavedChanges = true;
      this.updateLabel();
      this.setStatus("Unsaved changes");
    });

    [
      this.$priorityQueue(),
      this.$emergencyPrompt(),
      this.$holidayPrompt(),
      this.$globalVoiceName(),
      this.$mohSalesQueue()
    ].forEach(el => el.addEventListener("input", () => this.markDirty()));

    this.$globalLanguage().addEventListener("change", () => {
      this.updateVoiceOptions();
      this.markDirty();
    });

    this.$saveBtn().addEventListener("click", async () => await this.saveState());

    const queueFilterButton = this.$queueFilterButton();
    const queueFilterWrapper = this.shadowRoot.getElementById("queueFilterWrapper");

    if (queueFilterButton && queueFilterWrapper) {
      queueFilterButton.addEventListener("click", event => {
        event.stopPropagation();
        queueFilterWrapper.classList.toggle("open");
      });

      this.shadowRoot.addEventListener("click", event => {
        if (!queueFilterWrapper.contains(event.target)) {
          queueFilterWrapper.classList.remove("open");
        }
      });
    }

    const configToggle = this.shadowRoot.getElementById("configToggle");
    const configContent = this.shadowRoot.getElementById("configContent");

    if (configToggle && configContent) {
      configToggle.addEventListener("click", () => {
        configContent.classList.toggle("collapsed");
        configToggle.classList.toggle("collapsed");
      });
    }

    const callHistoryToggle = this.shadowRoot.getElementById("callHistoryToggle");
    const callHistoryContent = this.shadowRoot.getElementById("callHistoryContent");

    if (callHistoryToggle && callHistoryContent) {
      callHistoryToggle.addEventListener("click", () => {
        callHistoryContent.classList.toggle("collapsed");
        callHistoryToggle.classList.toggle("collapsed");
      });
    }
  }

  markDirty() {
    this.hasUnsavedChanges = true;
    this.setStatus("Unsaved changes");
  }

  async init() {
    try {
      await this.bootstrapSession();
      await this.loadEntryPoint(true);
      this.startWallboardStream();
      this.setStatus("Ready");
    } catch (err) {
      this.setStatus(`Load failed: ${err.message}`);
    }
  }

  $userInfo() { return this.shadowRoot.getElementById("userInfo"); }
  $roleBadge() { return this.shadowRoot.getElementById("roleBadge"); }
  $themeToggleBtn() { return this.shadowRoot.getElementById("themeToggleBtn"); }
  $toggle() { return this.shadowRoot.getElementById("emergencyToggle"); }
  $priorityQueue() { return this.shadowRoot.getElementById("priorityQueue"); }
  $emergencyPrompt() { return this.shadowRoot.getElementById("emergencyPrompt"); }
  $holidayPrompt() { return this.shadowRoot.getElementById("holidayPrompt"); }
  $globalLanguage() { return this.shadowRoot.getElementById("globalLanguage"); }
  $globalVoiceName() { return this.shadowRoot.getElementById("globalVoiceName"); }
  $mohSalesQueue() { return this.shadowRoot.getElementById("mohSalesQueue"); }
  $saveBtn() { return this.shadowRoot.getElementById("saveBtn"); }
  $stateLabel() { return this.shadowRoot.getElementById("stateLabel"); }
  $status() { return this.shadowRoot.getElementById("status"); }
  $queueFilterButton() { return this.shadowRoot.getElementById("queueFilterButton"); }
  $queueFilterMenu() { return this.shadowRoot.getElementById("queueFilterMenu"); }

  setStatus(msg) {
    this.$status().textContent = msg || "";
  }

  setWallboardStatus(msg) {
    const el = this.shadowRoot.getElementById("wallboardStatus");
    if (el) el.textContent = msg || "";
  }

  getVoiceOptions(lang) {
    return lang === "en-US" ? ["en-US-Daniel", "en-US-Maria"] : ["de-DE-Jonas", "de-DE-Emma"];
  }

  updateVoiceOptions(selected = "") {
    const lang = this.$globalLanguage().value || "de-DE";
    const options = this.getVoiceOptions(lang);
    const select = this.$globalVoiceName();
    const current = selected || select.value;
    this.setSelectOptions(select, options);
    select.value = options.includes(current) ? current : options[0];
  }

  getOverrideValue(overrides, name, fallback = "") {
    return overrides.find(o => o.name === name)?.value ?? fallback;
  }

  async resolveDesktopIdentity() {
    return {
      email: this.email || "",
      userId: this.userId || "",
      teamId: this.teamId || "",
      displayName: this.displayName || "Unknown User"
    };
  }

  async readJsonResponse(res) {
    const text = await res.text();
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch {
      return { error: text };
    }
  }

  async bootstrapSession() {
    if (this.isBootstrapping) return;
    this.isBootstrapping = true;

    try {
      const identity = await this.resolveDesktopIdentity();

      const res = await fetch(`${this.API_URL}/api/session/bootstrap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(identity)
      });

      const data = await this.readJsonResponse(res);

      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      if (!data.sessionToken) throw new Error("Bootstrap response did not include a session token");

      this.sessionToken = data.sessionToken;
      this.currentRole = data.role || "viewer";

      this.$userInfo().textContent = data.user?.displayName || "Unknown User";
      this.$roleBadge().textContent = this.currentRole === "supervisor" ? "Supervisor" : "Viewer";

      this.applyRoleState();
    } finally {
      this.isBootstrapping = false;
    }
  }

  applyRoleState() {
    const writable = ["supervisor", "admin"].includes(this.currentRole);
    [
      this.$toggle(),
      this.$priorityQueue(),
      this.$emergencyPrompt(),
      this.$holidayPrompt(),
      this.$globalLanguage(),
      this.$globalVoiceName(),
      this.$mohSalesQueue(),
      this.$saveBtn()
    ].forEach(el => el.disabled = !writable);
  }

  async authorizedFetch(path, options = {}, retryOn401 = true) {
    if (!this.sessionToken) await this.bootstrapSession();

    const makeRequest = () => fetch(`${this.API_URL}${path}`, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${this.sessionToken}`
      }
    });

    let res = await makeRequest();

    if (res.status === 401 && retryOn401) {
      await this.bootstrapSession();
      res = await makeRequest();
    }

    return res;
  }

  async loadEntryPoint(force = false) {
    if (!force && (this.isUpdating || this.hasUnsavedChanges)) return;

    const res = await this.authorizedFetch(`/api/entrypoint/${this.ENTRY_POINT_ID}`);
    const data = await this.readJsonResponse(res);

    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

    const overrides = Array.isArray(data.flowOverrideSettings) ? data.flowOverrideSettings : [];

    this.$priorityQueue().value = this.getOverrideValue(overrides, "Priority_Queue", "2");
    this.$toggle().checked = this.getOverrideValue(overrides, "EmergencyCase", "false") === "true";
    this.$emergencyPrompt().value = this.getOverrideValue(overrides, "EmergencyPrompt", "");
    this.$holidayPrompt().value = this.getOverrideValue(overrides, "HolidayPrompt", "");

    const lang = this.getOverrideValue(overrides, "Global_Language", "de-DE");
    const voice = this.getOverrideValue(overrides, "Global_VoiceName", "");

    this.$globalLanguage().value = ["de-DE", "en-US"].includes(lang) ? lang : "de-DE";
    this.updateVoiceOptions(voice);
    this.$mohSalesQueue().value = this.getOverrideValue(overrides, "Moh_Sales_Queue", "");

    this.updateLabel();
    this.hasUnsavedChanges = false;
  }

  updateLabel() {
    this.$stateLabel().textContent = this.$toggle().checked ? "ON" : "OFF";
  }

  toNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }

  setKpiClass(elementId, state) {
    const el = this.shadowRoot.getElementById(elementId);
    const card = el?.closest(".kpi");
    if (!card) return;

    card.classList.remove("kpi-green", "kpi-orange", "kpi-red", "kpi-critical");
    if (state) card.classList.add(state);
  }

  applyWallboardThresholds({ callsInQueue, loggedInAgents, availableAgents }) {
    const queue = this.toNumber(callsInQueue);
    const loggedIn = this.toNumber(loggedInAgents);
    const available = this.toNumber(availableAgents);

    this.setKpiClass(
      "kpiCallsInQueue",
      queue > 1 ? "kpi-critical" : queue === 1 ? "kpi-orange" : ""
    );

    this.setKpiClass(
      "kpiLoggedIn",
      loggedIn > 1 ? "kpi-green" : loggedIn === 1 ? "kpi-orange" : "kpi-red"
    );

    this.setKpiClass(
      "kpiAvailable",
      available > 1 ? "kpi-green" : available === 1 ? "kpi-orange" : "kpi-red"
    );
  }

  getAgentRowClass(state) {
    return String(state || "").trim().toLowerCase() === "available"
      ? "table-row agent-available"
      : "table-row agent-unavailable";
  }

  formatDuration(seconds) {
    const value = Number(seconds || 0);
    if (value < 60) return `${value}s`;
    const min = Math.floor(value / 60);
    const sec = value % 60;
    if (min < 60) return `${min}m ${sec}s`;
    return `${Math.floor(min / 60)}h ${min % 60}m`;
  }

  shortId(id) {
    return id ? String(id).slice(0, 8) : "-";
  }

  formatDateTime(timestamp) {
    const value = Number(timestamp || 0);
    if (!value) return "-";

    try {
      return new Date(value).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
    } catch {
      return "-";
    }
  }

  getAgentDuration(agent) {
    const base = Number(agent.lastActivityTime || agent.startTime || 0);
    return base > 0 ? Math.max(0, Math.floor((Date.now() - base) / 1000)) : 0;
  }


  normalizeText(value) {
    return String(value || "").trim().toLowerCase();
  }

  extractAllowedQueuesFromWallboardData(data = {}) {
    const directQueues =
      data.allowedQueues ||
      data.user?.allowedQueues ||
      data.user?.queues ||
      data.queues ||
      [];

    return Array.from(
      new Set(
        (Array.isArray(directQueues) ? directQueues : [])
          .map(q => String(q || "").trim())
          .filter(Boolean)
      )
    );
  }

  getCallQueueName(call) {
    return (
      call?.queue ||
      call?.queueName ||
      call?.firstQueue ||
      call?.firstQueueName ||
      call?.lastQueue ||
      call?.destinationQueue ||
      call?.queueDisplayName ||
      ""
    );
  }

  normalizeEmpty(value) {
    const text = String(value || "").trim();
    return text || "-";
  }

  getWrapupReason(call) {
    const value =
      call?.wrapupReason ||
      call?.wrapUpReason ||
      call?.wrapUpCodeName ||
      call?.wrapupCodeName ||
      call?.wrapUpCode ||
      call?.wrapupCode ||
      call?.wrapUpReasonName ||
      call?.wrapupReasonName ||
      call?.wrapUpData?.name ||
      call?.wrapupData?.name ||
      call?.wrapUp?.name ||
      call?.wrapup?.name ||
      "";

    return String(value || "").trim() || "-";
  }

  getHandleType(call) {
    const value =
      call?.handleType ||
      call?.contactHandleType ||
      call?.abandonedType ||
      "";

    return String(value || "").trim() || "-";
  }

  getTerminationReason(call) {
    const value =
      call?.terminationReason ||
      call?.taskLegTerminationReason ||
      call?.taskLegStatus ||
      "";

    return String(value || "").trim() || "-";
  }

  updateQueueFilterOptions() {
    const wrapper = this.shadowRoot.getElementById("queueFilterWrapper");
    const button = this.$queueFilterButton();
    const menu = this.$queueFilterMenu();

    if (!wrapper || !button || !menu) return;

    menu.innerHTML = "";

    const allowedQueues = Array.isArray(this.allowedQueueNames)
      ? this.allowedQueueNames.filter(Boolean)
      : [];

    if (allowedQueues.length <= 1) {
      wrapper.classList.remove("visible", "open");
      this.selectedQueueFilters = allowedQueues.length === 1 ? [allowedQueues[0]] : [];
      this.saveSelectedQueueFilters();
      button.textContent = allowedQueues.length === 1 ? `${allowedQueues[0]} ▾` : "Queues ▾";
      return;
    }

    wrapper.classList.add("visible");

    const selected = Array.isArray(this.selectedQueueFilters)
      ? this.selectedQueueFilters.filter(q => allowedQueues.includes(q))
      : [];

    this.selectedQueueFilters = selected.length ? selected : [allowedQueues[0]];
    this.saveSelectedQueueFilters();

    allowedQueues.forEach(queueName => {
      const label = document.createElement("label");
      label.className = "queue-filter-option";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = queueName;
      checkbox.checked = this.selectedQueueFilters.includes(queueName);

      checkbox.addEventListener("change", async () => {
        const checkedValues = Array.from(
          menu.querySelectorAll('input[type="checkbox"]:checked')
        ).map(input => input.value);

        if (!checkedValues.length) {
          checkbox.checked = true;
          return;
        }

        this.selectedQueueFilters = checkedValues;
        this.saveSelectedQueueFilters();
        this.updateQueueFilterButtonLabel();

        if (this.lastWallboardData) {
          this.processWallboardData(this.lastWallboardData);
        } else {
          await this.loadWallboard();
        }
      });

      const text = document.createElement("span");
      text.textContent = queueName;

      label.appendChild(checkbox);
      label.appendChild(text);
      menu.appendChild(label);
    });

    const hint = document.createElement("div");
    hint.className = "queue-filter-hint";
    hint.textContent = "Mehrere Queues können gleichzeitig ausgewählt werden.";
    menu.appendChild(hint);

    this.updateQueueFilterButtonLabel();
  }

  updateQueueFilterButtonLabel() {
    const button = this.$queueFilterButton();
    if (!button) return;

    const selected = Array.isArray(this.selectedQueueFilters)
      ? this.selectedQueueFilters
      : [];

    if (!selected.length) {
      button.textContent = "Queues ▾";
    } else if (selected.length === 1) {
      button.textContent = `${selected[0]} ▾`;
    } else {
      button.textContent = `${selected.length} Queues ▾`;
    }
  }

  getVisibleQueueNames() {
    const allowedQueues = Array.isArray(this.allowedQueueNames) ? this.allowedQueueNames : [];

    if (!allowedQueues.length) return [];

    const selected = Array.isArray(this.selectedQueueFilters)
      ? this.selectedQueueFilters.filter(q => allowedQueues.includes(q))
      : [];

    return selected.length ? selected : [allowedQueues[0]];
  }

  isQueueVisibleForCurrentUser(queueName) {
    const allowedQueues = Array.isArray(this.allowedQueueNames) ? this.allowedQueueNames : [];

    if (!allowedQueues.length) return false;

    const visibleQueues = this.getVisibleQueueNames();
    const normalizedQueue = this.normalizeText(queueName);

    return visibleQueues.some(q => this.normalizeText(q) === normalizedQueue);
  }

  filterCallsByAllowedQueues(calls) {
    const list = Array.isArray(calls) ? calls : [];

    return list.filter(call => {
      const queueName = this.getCallQueueName(call);
      return this.isQueueVisibleForCurrentUser(queueName);
    });
  }

  calculateQueueKpisFromVisibleCalls(waitingCalls, activeCalls, originalQueue = {}) {
    const visibleWaiting = Array.isArray(waitingCalls) ? waitingCalls : [];
    const visibleActive = Array.isArray(activeCalls) ? activeCalls : [];

    const waitingDurations = visibleWaiting
      .map(call => Number(call.waitingSeconds || 0))
      .filter(value => Number.isFinite(value) && value >= 0);

    const activeDurations = visibleActive
      .map(call => Math.round(Number(call.connectedDuration || 0) / 1000))
      .filter(value => Number.isFinite(value) && value >= 0);

    const avg = values => {
      if (!values.length) return 0;
      return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
    };

    return {
      callsInQueue: visibleWaiting.length,
      activeCalls: visibleActive.length,
      longestWaitingSeconds: waitingDurations.length ? Math.max(...waitingDurations) : 0,
      avgWaitSeconds: waitingDurations.length ? avg(waitingDurations) : 0,
      avgHandleSeconds: activeDurations.length ? avg(activeDurations) : Number(originalQueue.avgHandleSeconds || 0)
    };
  }

  renderWaitingCalls(calls) {
    const list = this.shadowRoot.getElementById("waitingCallList");
    list.innerHTML = `
      <div class="call-row call-header">
        <div>Status</div><div>Queue</div><div>Caller</div><div>Entry Point</div><div>Waiting</div><div>Task</div>
      </div>
    `;

    if (!calls.length) {
      const row = document.createElement("div");
      row.className = "call-row";
      row.innerHTML = `<div>No waiting calls</div><div></div><div></div><div></div><div></div><div></div>`;
      list.appendChild(row);
      return;
    }

    calls.forEach(call => {
      const row = document.createElement("div");
      row.className = "call-row";
      row.innerHTML = `
        <div>${call.status || "-"}</div>
        <div>${this.getCallQueueName(call) || "-"}</div>
        <div>${call.caller || "-"}</div>
        <div>${call.entryPoint || "-"}</div>
        <div>${this.formatDuration(call.waitingSeconds)}</div>
        <div>${this.shortId(call.id)}</div>
      `;
      list.appendChild(row);
    });
  }


  mergeActiveCallsForTimer(calls) {
    const now = Date.now();
    const incoming = Array.isArray(calls) ? calls : [];
    const next = new Map();

    incoming.forEach(call => {
      const id = String(call?.id || "");
      if (!id) return;

      const previous = this.activeCallRenderCache.get(id);
      const incomingSeconds = Number(call.handleSeconds || call.liveHandleSeconds || call.liveDurationSeconds || 0);

      let localStartMs = previous?.localStartMs;
      if (!localStartMs) {
        localStartMs = now - Math.max(0, incomingSeconds) * 1000;
      }

      next.set(id, {
        ...call,
        localStartMs,
        localLastSeenMs: now
      });
    });

    this.activeCallRenderCache = next;
    return Array.from(next.values());
  }

  rememberCallHistory(calls) {
    const rows = Array.isArray(calls) ? calls : [];

    if (rows.length > 0) {
      const existing = new Map(this.callHistoryRenderCache.map(row => [String(row.id || row.taskId || ""), row]));

      rows.forEach(row => {
        const id = String(row.id || row.taskId || "");
        if (!id) return;
        existing.set(id, row);
      });

      this.callHistoryRenderCache = Array.from(existing.values())
        .sort((a, b) => Number(b.createdTime || 0) - Number(a.createdTime || 0))
        .slice(0, 100);
      this.callHistoryCacheTs = Date.now();
      return this.callHistoryRenderCache;
    }

    if (this.callHistoryRenderCache.length && Date.now() - this.callHistoryCacheTs < 300000) {
      return this.callHistoryRenderCache;
    }

    return [];
  }

  getLiveDisplaySeconds(call) {
    const status = String(call?.status || "").toLowerCase();

    if (status === "connected" && Number(call?.localStartMs || 0) > 0) {
      return Math.max(0, Math.floor((Date.now() - Number(call.localStartMs)) / 1000));
    }

    const baseSeconds = Number(call?.handleSeconds || call?.liveHandleSeconds || call?.liveDurationSeconds || 0);
    const baseTimestamp = Number(call?.handleBaseTimestamp || 0);

    if (status === "connected" && baseTimestamp > 0) {
      return Math.max(0, baseSeconds + Math.floor((Date.now() - baseTimestamp) / 1000));
    }

    const start = Number(call?.connectedStartTime || call?.lastActivityTime || call?.createdTime || 0);
    if (status === "connected" && start > 0) {
      return Math.max(0, Math.floor((Date.now() - start) / 1000));
    }

    return baseSeconds;
  }

  updateActiveDurationCells() {
    const cells = this.shadowRoot.querySelectorAll(".live-duration");
    cells.forEach(cell => {
      const callId = String(cell.getAttribute("data-call-id") || "");
      const call = Array.from(this.activeCallRenderCache.values()).find(item => this.shortId(item.id) === callId);
      if (!call) return;
      cell.textContent = this.formatDuration(this.getLiveDisplaySeconds(call));
    });
  }

  startRobustActiveCallTimer() {
    if (this.activeCallTimerHandle) {
      clearInterval(this.activeCallTimerHandle);
    }

    this.activeCallTimerHandle = setInterval(() => {
      this.updateActiveDurationCells();

      if (!this.lastWallboardData) return;

      const rawActiveCalls = Array.isArray(this.lastWallboardData.taskList)
        ? this.lastWallboardData.taskList.filter(t => String(t.status || "").toLowerCase() === "connected")
        : [];
      const visibleActiveCalls = this.mergeActiveCallsForTimer(this.filterCallsByAllowedQueues(rawActiveCalls));
      this.renderActiveCalls(visibleActiveCalls);

      const rawCallHistory = Array.isArray(this.lastWallboardData.callHistoryList)
        ? this.lastWallboardData.callHistoryList
        : [];
      const visibleCallHistory = this.rememberCallHistory(this.filterCallsByAllowedQueues(rawCallHistory));
      this.renderCallHistory(visibleCallHistory);
    }, 1000);
  }

  renderCallHistory(calls) {
    const list = this.shadowRoot.getElementById("callHistoryList");
    if (!list) return;

    const maxRows = 75;
    const rows = (Array.isArray(calls) ? calls : []).slice(0, maxRows);

    list.innerHTML = `
      <div class="call-row history call-header">
        <div>Status</div><div>Queue</div><div>Caller</div><div>Agent</div><div>Wrapup Reason</div><div>Handle / Type</div><div>Termination Reason</div><div>Started</div><div>Duration</div><div>Task</div>
      </div>
    `;

    if (!rows.length) {
      const row = document.createElement("div");
      row.className = "call-row history";
      row.innerHTML = `<div>No calls in the last 24h</div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div>`;
      list.appendChild(row);
      return;
    }

    rows.forEach(call => {
      const row = document.createElement("div");
      row.className = "call-row history";
      const liveSeconds = Number(call.liveDurationSeconds || 0);
      const durationMs = Number(call.totalDuration || call.connectedDuration || call.queueDuration || 0);
      row.innerHTML = `
        <div>${call.status || "-"}</div>
        <div>${this.getCallQueueName(call) || "-"}</div>
        <div>${call.caller || "-"}</div>
        <div>${call.agent || "-"}</div>
        <div>${this.getWrapupReason(call)}</div>
        <div>${this.getHandleType(call)}</div>
        <div>${this.getTerminationReason(call)}</div>
        <div>${this.formatDateTime(call.createdTime)}</div>
        <div>${this.formatDuration(liveSeconds || Math.round(durationMs / 1000))}</div>
        <div>${this.shortId(call.id)}</div>
      `;
      list.appendChild(row);
    });
  }

  renderActiveCalls(calls) {
    const list = this.shadowRoot.getElementById("activeCallList");
    list.innerHTML = `
      <div class="call-row active call-header">
        <div>Status</div><div>Queue</div><div>Caller</div><div>Agent</div><div>Handle</div><div>Task</div>
      </div>
    `;

    if (!calls.length) {
      const row = document.createElement("div");
      row.className = "call-row active";
      row.innerHTML = `<div>No active calls</div><div></div><div></div><div></div><div></div><div></div>`;
      list.appendChild(row);
      return;
    }

    calls.forEach(call => {
      const row = document.createElement("div");
      row.className = "call-row active";
      const handleSeconds = this.getLiveDisplaySeconds(call);
      const fallbackSeconds = Math.round(Number(call.connectedDuration || 0) / 1000);
      row.innerHTML = `
        <div>${call.status || "-"}</div>
        <div>${this.getCallQueueName(call) || "-"}</div>
        <div>${call.caller || "-"}</div>
        <div>${call.agent || "-"}</div>
        <div><span class="live-duration" data-call-id="${this.shortId(call.id)}">${this.formatDuration(handleSeconds || fallbackSeconds)}</span></div>
        <div>${this.shortId(call.id)}</div>
      `;
      list.appendChild(row);
    });
  }

  processWallboardData(data) {
    this.wallboardLastDataTs = Date.now();
    this.lastWallboardData = data;

    const detectedQueues = this.extractAllowedQueuesFromWallboardData(data);
    this.allowedQueueNames = detectedQueues;

    this.updateQueueFilterOptions();

    const rawWaitingCalls = Array.isArray(data.waitingTaskList) ? data.waitingTaskList : [];

    const rawActiveCalls = Array.isArray(data.taskList)
      ? data.taskList.filter(t => String(t.status || "").toLowerCase() === "connected")
      : [];

    const rawCallHistory = Array.isArray(data.callHistoryList) ? data.callHistoryList : [];

    const visibleWaitingCalls = this.filterCallsByAllowedQueues(rawWaitingCalls);
    const visibleActiveCalls = this.mergeActiveCallsForTimer(this.filterCallsByAllowedQueues(rawActiveCalls));
    const visibleCallHistory = this.rememberCallHistory(this.filterCallsByAllowedQueues(rawCallHistory));
    const visibleQueueKpis = this.calculateQueueKpisFromVisibleCalls(
      visibleWaitingCalls,
      visibleActiveCalls,
      data.queue || {}
    );

    const callsInQueue = visibleQueueKpis.callsInQueue;
    const loggedInAgents = data.agents?.loggedIn ?? 0;
    const availableAgents = data.agents?.available ?? 0;

    this.shadowRoot.getElementById("kpiCallsInQueue").textContent = callsInQueue;
    this.shadowRoot.getElementById("kpiActiveCalls").textContent = visibleQueueKpis.activeCalls;
    this.shadowRoot.getElementById("kpiLongestWaiting").textContent = this.formatDuration(visibleQueueKpis.longestWaitingSeconds);
    this.shadowRoot.getElementById("kpiAvgWait").textContent = this.formatDuration(visibleQueueKpis.avgWaitSeconds);
    this.shadowRoot.getElementById("kpiAvgHandle").textContent = this.formatDuration(visibleQueueKpis.avgHandleSeconds);
    this.shadowRoot.getElementById("kpiLoggedIn").textContent = loggedInAgents;
    this.shadowRoot.getElementById("kpiAvailable").textContent = availableAgents;

    if (typeof this.updateKpiState === "function") {
      this.updateKpiState("kpiCardCallsInQueue", callsInQueue, "queue");
      this.updateKpiState("kpiCardLoggedIn", loggedInAgents, "agents");
      this.updateKpiState("kpiCardAvailable", availableAgents, "agents");
    } else if (typeof this.applyWallboardThresholds === "function") {
      this.applyWallboardThresholds({ callsInQueue, loggedInAgents, availableAgents });
    }

    const agentList = this.shadowRoot.getElementById("agentList");
    agentList.innerHTML = `
      <div class="table-row table-header">
        <div>Name</div><div>Status</div><div>Team</div><div>Active Since</div>
      </div>
    `;

    const agents = Array.isArray(data.agentList) ? data.agentList : [];

    if (!agents.length) {
      const row = document.createElement("div");
      row.className = "table-row";
      row.innerHTML = `<div>No active agents</div><div></div><div></div><div></div>`;
      agentList.appendChild(row);
    } else {
      agents.forEach(agent => {
        const row = document.createElement("div");
        row.className =
          String(agent.state || "").toLowerCase() === "available"
            ? "table-row agent-available"
            : "table-row agent-unavailable";
        row.innerHTML = `
          <div>${agent.name || agent.login || "-"}</div>
          <div>${agent.state || "-"}</div>
          <div>${agent.team || "-"}</div>
          <div>${this.formatDuration(this.getAgentDuration(agent))}</div>
        `;
        agentList.appendChild(row);
      });
    }

    this.renderWaitingCalls(visibleWaitingCalls);
    this.renderCallHistory(visibleCallHistory);
    this.renderActiveCalls(visibleActiveCalls);

    const visibleQueues = this.getVisibleQueueNames();
    const queueFilterInfo = visibleQueues.length
      ? ` • Queues: ${visibleQueues.join(", ")}`
      : " • No queue assignment detected";

    this.setWallboardStatus(`Live • Updated ${new Date().toLocaleTimeString()}${queueFilterInfo}`);

    setTimeout(() => {
      this.runWallboardWatchdog().catch(() => {});
    }, 500);
  }



  bindFocusResumeRefresh() {
    if (this.boundFocusResumeRefresh) return;

    this.boundFocusResumeRefresh = () => {
      this.scheduleFocusResumeRefresh("focus-resume");
    };

    window.addEventListener("focus", this.boundFocusResumeRefresh, true);
    window.addEventListener("pageshow", this.boundFocusResumeRefresh, true);
    document.addEventListener("visibilitychange", this.boundFocusResumeRefresh, true);

    // WXCC can switch between internal widgets without browser focus changing.
    this.addEventListener("pointerenter", this.boundFocusResumeRefresh);
    this.addEventListener("mouseenter", this.boundFocusResumeRefresh);
  }

  removeFocusResumeRefresh() {
    if (!this.boundFocusResumeRefresh) return;

    window.removeEventListener("focus", this.boundFocusResumeRefresh, true);
    window.removeEventListener("pageshow", this.boundFocusResumeRefresh, true);
    document.removeEventListener("visibilitychange", this.boundFocusResumeRefresh, true);
    this.removeEventListener("pointerenter", this.boundFocusResumeRefresh);
    this.removeEventListener("mouseenter", this.boundFocusResumeRefresh);
    this.boundFocusResumeRefresh = null;
  }

  scheduleFocusResumeRefresh(reason = "focus-resume") {
    if (document.visibilityState && document.visibilityState === "hidden") return;
    if (!this.sessionToken) return;

    const now = Date.now();
    if (now - this.focusResumeLastRefreshTs < 2500) return;

    if (this.focusResumeRefreshHandle) {
      clearTimeout(this.focusResumeRefreshHandle);
    }

    this.focusResumeRefreshHandle = setTimeout(async () => {
      this.focusResumeRefreshHandle = null;
      this.focusResumeLastRefreshTs = Date.now();

      await this.safeWallboardRefresh(`${reason}-immediate`);
      setTimeout(() => this.safeWallboardRefresh(`${reason}-followup`), 1200);
    }, 150);
  }


  getWallboardArrays(data = this.lastWallboardData) {
    const agents = Array.isArray(data?.agents) ? data.agents : Array.isArray(data?.agentList) ? data.agentList : [];
    return {
      agents,
      activeCalls: Array.isArray(data?.taskList) ? data.taskList : [],
      waitingCalls: Array.isArray(data?.waitingTaskList) ? data.waitingTaskList : [],
      callHistory: Array.isArray(data?.callHistoryList) ? data.callHistoryList : []
    };
  }

  buildWidgetSignature(data = this.lastWallboardData) {
    const { agents, activeCalls, waitingCalls, callHistory } = this.getWallboardArrays(data);
    return [
      agents.map(a => `${a.name || a.login || ""}:${a.state || ""}`).sort().join("|"),
      activeCalls.map(c => `${c.id || ""}:${c.status || ""}`).sort().join("|"),
      waitingCalls.map(c => `${c.id || ""}:${c.waitingSeconds || 0}`).sort().join("|"),
      callHistory.slice(0, 10).map(c => `${c.id || ""}:${c.status || ""}:${c.endedTime || ""}`).sort().join("|")
    ].join("#");
  }

  analyzeWidgetState() {
    const now = Date.now();
    const { agents, activeCalls, waitingCalls, callHistory } = this.getWallboardArrays();
    const connectedAgents = agents.filter(a => String(a.state || "").toLowerCase() === "connected");
    const liveActive = activeCalls.filter(c => String(c.status || "").toLowerCase() === "connected");
    const connectedHistory = callHistory.filter(c => String(c.status || "").toLowerCase() === "connected");
    const anomalies = [];

    if (!this.lastWallboardData) anomalies.push("no-wallboard-data");
    if (!agents.length) anomalies.push("no-agent-data");
    if (connectedAgents.length && !liveActive.length) anomalies.push("connected-agent-without-active-call");
    if (connectedHistory.length && !liveActive.length && !connectedAgents.length) anomalies.push("history-connected-stale");
    if (waitingCalls.some(c => Number(c.waitingSeconds || 0) < 0)) anomalies.push("negative-waiting-time");

    const signature = this.buildWidgetSignature();
    if (signature !== this.widgetLastSignature) {
      this.widgetLastSignature = signature;
      this.widgetLastSignatureTs = now;
    }
    if (this.widgetLastSignatureTs && now - this.widgetLastSignatureTs > 15000) anomalies.push("unchanged-ui-signature");

    return {
      now,
      counts: {
        agents: agents.length,
        connectedAgents: connectedAgents.length,
        activeCalls: activeCalls.length,
        liveActive: liveActive.length,
        waitingCalls: waitingCalls.length,
        callHistory: callHistory.length,
        connectedHistory: connectedHistory.length
      },
      anomalies,
      lastDataAgeMs: this.wallboardLastDataTs ? now - this.wallboardLastDataTs : null,
      eventSourceReadyState: this.wallboardEventSource ? this.wallboardEventSource.readyState : null
    };
  }

  async refreshForAnomalies(analysis) {
    const now = Date.now();
    for (const anomaly of analysis.anomalies) {
      if (!this.widgetAnomalySince[anomaly]) this.widgetAnomalySince[anomaly] = now;
    }
    Object.keys(this.widgetAnomalySince).forEach(key => {
      if (!analysis.anomalies.includes(key)) delete this.widgetAnomalySince[key];
    });

    const trigger = analysis.anomalies.find(anomaly => {
      const age = now - (this.widgetAnomalySince[anomaly] || now);
      if (anomaly === "connected-agent-without-active-call") return age > 1500;
      if (anomaly === "history-connected-stale") return age > 2500;
      if (anomaly === "no-agent-data") return age > 5000;
      if (anomaly === "unchanged-ui-signature") return age > 0;
      if (anomaly === "no-wallboard-data") return age > 0;
      return age > 4000;
    });

    if (trigger) {
      this.widgetWatchdogCounters[trigger] = (this.widgetWatchdogCounters[trigger] || 0) + 1;
      this.recordClientSseDebug("watchdog-anomaly-refresh", { trigger, analysis });
      await this.safeWallboardRefresh(`anomaly:${trigger}`);
    }
  }

  startWallboardWatchdog() {
    if (this.wallboardWatchdogHandle) {
      clearInterval(this.wallboardWatchdogHandle);
    }

    this.wallboardWatchdogHandle = setInterval(() => {
      this.runWallboardWatchdog();
    }, 5000);
  }

  async runWallboardWatchdog() {
    if (!this.sessionToken) return;

    const now = Date.now();
    const hasEventSource = !!this.wallboardEventSource;
    const staleData = !this.wallboardLastDataTs || now - this.wallboardLastDataTs > 8000;
    const analysis = this.analyzeWidgetState();

    this.recordClientSseDebug("watchdog-check", analysis);

    if (!hasEventSource || staleData) {
      await this.safeWallboardRefresh(!hasEventSource ? "sse-disconnected" : "stale-data");
    }

    await this.refreshForAnomalies(analysis);
  }

  async safeWallboardRefresh(reason = "watchdog") {
    const now = Date.now();

    if (this.wallboardManualRefreshInFlight) return;
    if (now - this.wallboardLastManualRefreshTs < 2000) return;

    this.wallboardManualRefreshInFlight = true;
    this.wallboardLastManualRefreshTs = now;

    try {
      await this.loadWallboard(`watchdog:${reason}`);
    } finally {
      this.wallboardManualRefreshInFlight = false;
    }
  }

  async loadWallboard(reason = "manual") {
    this.recordClientSseDebug("wallboard-fetch-start", { reason });
    try {
      const res = await this.authorizedFetch(`/api/wallboard`);
      const data = await this.readJsonResponse(res);

      if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);

      this.recordClientSseDebug("wallboard-fetch-success", { reason, stale: data?.stale === true, status: res.status });
      this.processWallboardData(data);
      if (data.stale === true) {
        this.setWallboardStatus(`Recovered with cached data ${new Date().toLocaleTimeString()} • ${data.lastError || data.staleReason || ""}`.trim());
      } else if (reason && reason !== "manual") {
        this.setWallboardStatus(`Recovered via ${reason} ${new Date().toLocaleTimeString()}`);
      }
    } catch (err) {
      this.recordClientSseDebug("wallboard-fetch-error", { reason, message: err.message });
      this.setWallboardStatus(`Dashboard failed: ${err.message}`);
    }
  }


  recordClientSseDebug(type, details = {}) {
    const item = {
      ts: Date.now(),
      iso: new Date().toISOString(),
      type,
      ...details
    };

    this.sseClientDebugEvents.push(item);
    while (this.sseClientDebugEvents.length > this.sseClientDebugMax) {
      this.sseClientDebugEvents.shift();
    }

    try {
      window.__WXCC_SUPERVISOR_WIDGET_DEBUG__ = {
        frontendBuildId: typeof FRONTEND_BUILD_ID !== "undefined" ? FRONTEND_BUILD_ID : "",
        events: this.sseClientDebugEvents,
        lastWallboardData: this.lastWallboardData,
        agentCount: Array.isArray(this.lastWallboardData?.agents) ? this.lastWallboardData.agents.length : null,
        agentListCount: Array.isArray(this.lastWallboardData?.agentList) ? this.lastWallboardData.agentList.length : null,
        eventSourceReadyState: this.wallboardEventSource ? this.wallboardEventSource.readyState : null,
        lastDataAgeMs: this.wallboardLastDataTs ? Date.now() - this.wallboardLastDataTs : null,
        watchdogCounters: this.widgetWatchdogCounters,
        watchdogAnalysis: this.analyzeWidgetState ? this.analyzeWidgetState() : null
      };
    } catch {
      // ignore
    }

    return item;
  }

  startWallboardStream() {
    if (this.wallboardEventSource) {
      this.wallboardEventSource.close();
      this.wallboardEventSource = null;
    }

    if (this.wallboardReconnectHandle) {
      clearTimeout(this.wallboardReconnectHandle);
      this.wallboardReconnectHandle = null;
    }

    if (!this.sessionToken) {
      this.setWallboardStatus("Live dashboard failed: missing session token");
      return;
    }

    const url = `${this.API_URL}/api/wallboard/stream?token=${encodeURIComponent(this.sessionToken)}`;
    this.recordClientSseDebug("eventsource-open-start", { url: url.replace(/token=[^&]+/, "token=***") });
    const source = new EventSource(url);
    this.wallboardEventSource = source;

    source.addEventListener("ready", () => {
      this.recordClientSseDebug("eventsource-ready", { readyState: source.readyState });
      this.wallboardLastEventTs = Date.now();
      this.setWallboardStatus("Live dashboard connected");
    });

    source.addEventListener("wallboard", event => {
      this.recordClientSseDebug("eventsource-wallboard", { bytes: event?.data ? event.data.length : 0, readyState: source.readyState });
      this.wallboardLastEventTs = Date.now();
      try {
        const data = JSON.parse(event.data);
        this.processWallboardData(data);
      } catch (err) {
        this.setWallboardStatus(`Live dashboard parse failed: ${err.message}`);
      }
    });

    source.addEventListener("wxcc-event", () => {
      this.recordClientSseDebug("eventsource-wxcc-event", { readyState: source.readyState });
      this.wallboardLastEventTs = Date.now();
      this.setWallboardStatus("WXCC event received. Refreshing...");
      this.safeWallboardRefresh("wxcc-event-immediate");
      setTimeout(() => this.safeWallboardRefresh("wxcc-event-followup"), 1200);
    });

    source.addEventListener("event-refresh", () => {
      this.recordClientSseDebug("eventsource-event-refresh", { readyState: source.readyState });
      this.wallboardLastEventTs = Date.now();
      this.setWallboardStatus(`Event refresh completed ${new Date().toLocaleTimeString()}`);
    });

    source.addEventListener("error", event => {
      this.recordClientSseDebug("eventsource-error", { readyState: source.readyState, message: event?.message || "" });
      if (this.wallboardEventSource) {
        this.wallboardEventSource.close();
        this.wallboardEventSource = null;
      }

      this.setWallboardStatus("Live dashboard disconnected. Reconnecting...");
      this.safeWallboardRefresh("sse-error");

      this.wallboardReconnectHandle = setTimeout(() => {
        this.startWallboardStream();
      }, 5000);
    });
  }

  async saveState() {
    if (!["supervisor", "admin"].includes(this.currentRole)) {
      this.setStatus("No write permission");
      return;
    }

    const flowOverrideSettings = [
      { name: "Priority_Queue", type: "INTEGER", value: String(Number(this.$priorityQueue().value)) },
      { name: "EmergencyCase", type: "BOOLEAN", value: this.$toggle().checked ? "true" : "false" },
      { name: "HolidayPrompt", type: "STRING", value: this.$holidayPrompt().value },
      { name: "Global_VoiceName", type: "STRING", value: this.$globalVoiceName().value },
      { name: "EmergencyPrompt", type: "STRING", value: this.$emergencyPrompt().value },
      { name: "Global_Language", type: "STRING", value: this.$globalLanguage().value },
      { name: "Moh_Sales_Queue", type: "STRING", value: this.$mohSalesQueue().value }
    ];

    try {
      this.isUpdating = true;
      this.$saveBtn().disabled = true;
      this.setStatus("Saving...");

      const res = await this.authorizedFetch(`/api/entrypoint/${this.ENTRY_POINT_ID}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flowOverrideSettings })
      });

      const data = await this.readJsonResponse(res);

      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

      this.hasUnsavedChanges = false;
      await this.loadEntryPoint(true);
      this.setStatus("Saved successfully ✔");
    } catch (err) {
      this.setStatus(`Update failed ❌ ${err.message || ""}`.trim());
    } finally {
      this.isUpdating = false;
      this.applyRoleState();
    }
  }

  startPolling() {
    // Disabled: entry point auto-polling is intentionally off.
    // The entry point is loaded once during init and again after Save.
  }

  startWallboardPolling() {
    // Disabled: wallboard updates are delivered through Server-Sent Events.
  }
}

if (!customElements.get("supervisor-access-widget-v2")) {
  customElements.define("supervisor-access-widget-v2", SupervisorAccessWidget);
}
