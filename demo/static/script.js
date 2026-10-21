(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  let latestResult = null;
  let latestSummary = "";
  let activeRequest = false;
  let toastTimer = null;

  const SAMPLE_LOG = [
    "2026-10-22 10:25:30 ERROR PaymentService: Failed transaction",
    "2026-10-22 10:25:31 WARN PaymentService: Retrying transaction",
    "2026-10-22 10:25:36 FATAL PaymentService: Unrecoverable database error",
    "2026-10-22 10:25:42 SECURITY AuthService: Multiple failed login attempts",
    "2026-10-22 10:25:45 INFO AuthService: Rate limit applied"
  ].join("\n");

  function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value == null ? "" : String(value);
  }

  function showToast(message) {
    const toast = $("toast");
    toast.textContent = message;
    toast.classList.add("visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 2600);
  }

  function setBusy(busy, message) {
    activeRequest = busy;
    $("analyzeButton").disabled = busy;
    $("analyzeButton").classList.toggle("is-loading", busy);
    $("analyzeButtonText").textContent = busy ? (message || "Analyzing…") : "Analyze logs";
    $("statusText").textContent = busy ? "Running…" : $("statusText").textContent;
    $("statusIcon").textContent = busy ? "◐" : "◌";
    $("resultBadge").dataset.state = busy ? "running" : $("resultBadge").dataset.state;
    $("resultBadge").textContent = busy ? "RUNNING" : $("resultBadge").textContent;
  }

  function updateInputStats() {
    const value = $("logText").value;
    const lines = value.length ? value.split(/\r\n|\r|\n/).length : 0;
    setText("inputStats", `${lines.toLocaleString()} ${lines === 1 ? "line" : "lines"} · ${value.length.toLocaleString()} characters`);
  }

  async function checkConnection() {
    const pill = $("modelStatus");
    try {
      const response = await fetch("/health", { headers: { Accept: "application/json" } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error("Health endpoint unavailable");

      const healthy = String(data.status || "").toLowerCase() === "healthy";
      pill.dataset.state = healthy ? "online" : "degraded";
      setText("modelStatusText", healthy ? "Service reachable" : "Service degraded");
      $("healthDot").dataset.state = healthy ? "online" : "degraded";
      setText("healthStatus", healthy ? "API health check passed" : "API reports degraded status");
      pill.title = data.model ? `Configured model: ${data.model}` : "API health endpoint responded";
    } catch {
      pill.dataset.state = "offline";
      setText("modelStatusText", "Service unavailable");
      $("healthDot").dataset.state = "offline";
      setText("healthStatus", "Could not reach the API health endpoint");
      pill.title = "The API health endpoint did not respond successfully";
    }
  }

  function setError(message) {
    setText("statusText", "Failed");
    setText("statusIcon", "✕");
    setText("resultBadge", "FAILED");
    $("resultBadge").dataset.state = "failed";
    setText("summaryContent", message);
    setText("detailsContent", "No incident details are available because this request failed.");
    setText("patternCounts", "");
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No pattern counts available.";
    $("patternCounts").appendChild(empty);
    setText("securityContent", "No security report available.");
    setText("priorityValue", "UNKNOWN");
    $("priorityValue").dataset.priority = "unknown";
    setBusy(false);
  }

  async function requestAnalysis({ text, file }) {
    if (activeRequest) return;
    const quick = $("quickMode").checked;
    if (!file && (!text || !text.trim())) {
      showToast("Paste log text or choose a file first.");
      $("logText").focus();
      return;
    }

    $("analysisSection").classList.remove("hidden");
    $("analysisSection").scrollIntoView({ behavior: "smooth", block: "start" });
    setBusy(true, file ? "Uploading…" : "Analyzing…");
    setText("summaryContent", "Analysis is running. Results will appear here.");
    setText("detailsContent", "Waiting for the analyzer…");
    setText("patternCounts", "");
    setText("securityContent", "Waiting for the analyzer…");

    try {
      let response;
      if (file) {
        const form = new FormData();
        form.append("file", file);
        form.append("quick", quick ? "true" : "false");
        response = await fetch("/analyze", { method: "POST", body: form });
      } else {
        response = await fetch("/analyze/text", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({
            log_text: text,
            analysis_type: quick ? "quick" : "full"
          })
        });
      }

      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = typeof payload.detail === "string" ? payload.detail : "The analysis request failed.";
        throw new Error(detail);
      }
      const data = payload.data || payload;
      if (!data || typeof data !== "object") throw new Error("The server returned an unexpected response.");
      latestResult = data;
      displayResults(data, quick);
      showToast("Analysis complete.");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unexpected analysis error.");
      showToast("Analysis failed. See the summary panel.");
    } finally {
      setBusy(false);
    }
  }

  function getIncidentCount(data) {
    const signals = data.root_cause_signals || {};
    const count = Number(signals.error_count);
    if (Number.isFinite(count) && count >= 0) return count;

    const events = Array.isArray(data.events) ? data.events : [];
    const incidentSeverities = new Set(["ERROR", "ERR", "EXCEPTION", "FATAL", "CRITICAL"]);
    return events.filter((item) => incidentSeverities.has(String(item && item.severity || "").toUpperCase())).length;
  }

  function renderPatternCounts(errors) {
    const container = $("patternCounts");
    container.replaceChildren();
    const entries = Object.entries(errors).filter(([, value]) => Number.isFinite(Number(value)));
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "No pattern counts were returned.";
      container.appendChild(empty);
      return;
    }

    for (const [name, rawValue] of entries) {
      const card = document.createElement("div");
      card.className = "pattern-card";
      const label = document.createElement("span");
      label.textContent = name.replaceAll("_", " ");
      const value = document.createElement("strong");
      value.textContent = Number(rawValue).toLocaleString();
      card.append(label, value);
      container.appendChild(card);
    }
  }

  function displayResults(data, quick) {
    setText("statusText", "Complete");
    setText("statusIcon", "✓");
    setText("resultBadge", "COMPLETE");
    $("resultBadge").dataset.state = "complete";
    setText("lineCount", Number(data.total_lines || 0).toLocaleString());
    setText("errorCount", getIncidentCount(data).toLocaleString());
    setText("timeText", Number.isFinite(Number(data.processing_time_seconds))
      ? `${Number(data.processing_time_seconds).toFixed(2)}s`
      : "—");
    setText("modeText", quick ? "Quick · rule-based" : "Full · configured provider");
    latestSummary = String(data.summary || "No summary was returned.");
    if (data.priority) latestSummary = `Priority: ${String(data.priority).toUpperCase()}\n\n${latestSummary}`;
    setText("summaryContent", latestSummary);
    setText("detailsContent", data.detailed_analysis || "No incident details were returned.");
    setText("priorityValue", String(data.priority || "unknown").toUpperCase());
    $("priorityValue").dataset.priority = String(data.priority || "unknown").toLowerCase();

    const errors = data.errors_found && typeof data.errors_found === "object" ? data.errors_found : {};
    renderPatternCounts(errors);

    const security = data.security_findings;
    if (security && typeof security === "object") {
      const findings = Array.isArray(security.findings) ? security.findings : [];
      const securitySummary = [
        `Risk level: ${security.risk_level || "unknown"}`,
        `Security issues flagged: ${security.has_security_issues ? "yes" : "no"}`,
        `Finding types: ${findings.length}`,
        ...findings.map((finding) => `\n• ${finding.type || "finding"} — ${finding.description || "No description"} (count: ${finding.count ?? "n/a"})`)
      ].join("\n");
      setText("securityContent", securitySummary);
    } else {
      setText("securityContent", "No security report was returned.");
    }
  }

  function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach((button) => {
      const active = button.dataset.tab === tabId;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".tab-pane").forEach((panel) => {
      const active = panel.id === tabId;
      panel.classList.toggle("active", active);
      panel.hidden = !active;
    });
  }

  function loadSample() {
    $("logText").value = SAMPLE_LOG;
    updateInputStats();
    $("logText").focus();
    showToast("Sample log loaded.");
  }

  function downloadResult() {
    if (!latestResult) {
      showToast("Run an analysis before exporting.");
      return;
    }
    const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "log-triage-report.json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function copySummary() {
    if (!latestSummary) {
      showToast("Run an analysis before copying a summary.");
      return;
    }
    try {
      await navigator.clipboard.writeText(latestSummary);
      showToast("Summary copied.");
    } catch {
      showToast("Clipboard access was blocked by the browser.");
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("analyzeButton").addEventListener("click", () => requestAnalysis({ text: $("logText").value }));
    $("sampleButton").addEventListener("click", loadSample);
    $("clearButton").addEventListener("click", () => {
      $("logText").value = "";
      updateInputStats();
      $("logText").focus();
    });
    $("logText").addEventListener("input", updateInputStats);
    $("copySummaryButton").addEventListener("click", copySummary);
    $("downloadButton").addEventListener("click", downloadResult);

    document.querySelectorAll(".tab-btn").forEach((button) => {
      button.addEventListener("click", () => switchTab(button.dataset.tab));
    });

    const fileInput = $("fileInput");
    const dropArea = $("dropArea");
    $("browseButton").addEventListener("click", (event) => {
      event.stopPropagation();
      fileInput.click();
    });
    dropArea.addEventListener("click", (event) => {
      if (event.target.closest("button")) return;
      fileInput.click();
    });
    dropArea.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInput.click();
      }
    });
    dropArea.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropArea.classList.add("dragging");
    });
    dropArea.addEventListener("dragleave", () => dropArea.classList.remove("dragging"));
    dropArea.addEventListener("drop", (event) => {
      event.preventDefault();
      dropArea.classList.remove("dragging");
      const file = event.dataTransfer && event.dataTransfer.files[0];
      if (file) {
        setText("selectedFile", file.name);
        requestAnalysis({ file });
      }
    });
    fileInput.addEventListener("change", () => {
      const file = fileInput.files && fileInput.files[0];
      if (file) {
        setText("selectedFile", file.name);
        requestAnalysis({ file });
      }
    });

    updateInputStats();
    checkConnection();
    window.setInterval(checkConnection, 30000);
  });
})();