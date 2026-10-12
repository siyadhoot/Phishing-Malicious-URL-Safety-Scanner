(() => {
  "use strict";

  // Flask serves both the frontend and API, so this remains same-origin locally and in deployment.
  const API_BASE_URL = "";
  const REQUEST_TIMEOUT_MS = 10000;
  const ALLOWED_VERDICTS = new Set(["phishing", "legitimate"]);

  // Keep the pure URL/response helpers usable in Node's built-in test runner.
  if (typeof document === "undefined") {
    if (typeof module !== "undefined" && module.exports) module.exports = { validateUrl, normalizeResponse, formatProbability, resultPresentation };
    return;
  }

  const form = document.querySelector("#scan-form");
  const input = document.querySelector("#url-input");
  const button = document.querySelector("#scan-button");
  const error = document.querySelector("#url-error");
  const status = document.querySelector("#scan-status");
  const result = document.querySelector("#result");
  const resultHeading = document.querySelector("#result-heading");
  const verdictTag = document.querySelector("#verdict-tag");
  const summary = document.querySelector("#result-summary");
  const verdictSource = document.querySelector("#verdict-source");
  const modelDiagnostics = document.querySelector("#model-diagnostics");
  const indicatorsWrap = document.querySelector("#indicators-wrap");
  const indicators = document.querySelector("#indicators");
  const scanAgain = document.querySelector("#scan-again");
  const modeLabel = document.querySelector("#mode-label");
  const normalizedUrl = document.querySelector("#normalized-url");
  const estimateWrap = document.querySelector("#estimate-wrap");
  const estimateValue = document.querySelector("#estimate-value");

  modeLabel.textContent = "";

  function validateUrl(value) {
    const raw = String(value ?? "");
    if (/[\u0000-\u001f\u007f\\]/.test(raw)) return { valid: false, message: "The URL contains invalid characters." };
    const text = raw.trim();
    if (!text) return { valid: false, message: "Enter a URL to check." };
    if (text.length > 2048) return { valid: false, message: "The URL is too long (maximum 2048 characters)." };
    if (/\s/.test(text)) return { valid: false, message: "Remove spaces inside the URL and try again." };
    if (/^[a-z][a-z0-9+.-]*:/i.test(text) && !/^https?:\/\//i.test(text)) return { valid: false, message: "Only http:// and https:// web addresses are supported." };
    const candidate = /^https?:\/\//i.test(text) ? text : `https://${text}`;
    let parsed;
    try { parsed = new URL(candidate); } catch { return { valid: false, message: "Enter a valid web address, such as example.com." }; }
    if (!["http:", "https:"].includes(parsed.protocol)) return { valid: false, message: "Only http:// and https:// web addresses are supported." };
    if (parsed.username || parsed.password) return { valid: false, message: "URLs containing a username or password are not accepted." };
    if (!parsed.hostname) return { valid: false, message: "Enter a valid hostname." };
    // Keep the user's URL spelling after parser validation. `URL.href` inserts a
    // trailing slash on host-only URLs, which changes URL-count model features.
    // The backend performs the authoritative canonicalization for display.
    return { valid: true, url: candidate };
  }

  function formatProbability(probability) {
    if (typeof probability !== "number" || !Number.isFinite(probability) || probability < 0 || probability > 1) return null;
    const percentage = probability * 100;
    if (percentage < 0.01) return "<0.01%";
    if (percentage > 99.99) return ">99.99%";
    return `${percentage.toFixed(2)}%`;
  }

  function normalizeResponse(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("The server returned an unexpected response. Please try again later.");
    // A present final verdict always wins. Legacy fields are consulted only when it is absent.
    const hasFinalVerdict = Object.prototype.hasOwnProperty.call(data, "verdict");
    const rawVerdict = hasFinalVerdict ? data.verdict : (data.prediction ?? data.label);
    const legacyVerdict = String(rawVerdict ?? "").trim().toLowerCase();
    const verdict = hasFinalVerdict
      ? legacyVerdict
      : (({ safe: "legitimate", malicious: "phishing" })[legacyVerdict] || legacyVerdict);
    if (!ALLOWED_VERDICTS.has(verdict)) throw new Error("The server response did not include a recognized verdict.");
    const policyOverride = data.policy_override === true;
    const modelPredictionRaw = String(data.model_prediction ?? data.prediction ?? "").toLowerCase();
    const modelPrediction = ALLOWED_VERDICTS.has(modelPredictionRaw) ? modelPredictionRaw : null;
    const modelProbabilityValue = typeof data.model_phishing_probability === "number"
      ? data.model_phishing_probability : data.phishing_probability;
    const modelPhishingProbability = typeof modelProbabilityValue === "number"
      && Number.isFinite(modelProbabilityValue) && modelProbabilityValue >= 0 && modelProbabilityValue <= 1
      ? modelProbabilityValue : null;
    const hasExplicitConfidence = Object.prototype.hasOwnProperty.call(data, "confidence");
    const explicitConfidence = typeof data.confidence === "number"
      && Number.isFinite(data.confidence) && data.confidence >= 0 && data.confidence <= 1
      ? data.confidence : null;
    const modelConfidence = explicitConfidence !== null
      ? explicitConfidence
      : (hasExplicitConfidence || modelPhishingProbability === null || !["phishing", "legitimate"].includes(modelPrediction)
        ? null
        : (modelPrediction === "phishing" ? modelPhishingProbability : 1 - modelPhishingProbability));
    const list = Array.isArray(data.indicators) ? data.indicators : [];
    return {
      verdict,
      normalizedUrl: typeof data.normalized_url === "string" ? data.normalized_url : (typeof data.url === "string" ? data.url : ""),
      summary: typeof data.summary === "string" ? data.summary.slice(0, 1000) : "",
      indicators: list.filter(item => typeof item === "string").slice(0, 12).map(item => item.slice(0, 240)),
      verdictSource: data.verdict_source === "team_rule" ? "team_rule" : "ml_model",
      policyOverride,
      policyReason: typeof data.policy_reason === "string" ? data.policy_reason.slice(0, 1000) : "",
      modelPrediction,
      modelPhishingProbability,
      modelConfidence
    };
  }

  function resultPresentation(data) {
    const titles = {
      phishing: "PHISHING",
      legitimate: "LEGITIMATE"
    };
    if (!data || !ALLOWED_VERDICTS.has(data.verdict)) {
      throw new Error("The scan result does not include a recognized verdict.");
    }
    const fromTeamRule = data.policyOverride === true || data.verdictSource === "team_rule";
    return {
      title: titles[data.verdict],
      verdict: data.verdict,
      fromTeamRule,
      sourceText: fromTeamRule
        ? (data.policyReason || "Team-configured demonstration rule; this is not an ML verdict.")
        : "",
      summary: data.summary || "No result explanation was provided.",
      probabilityText: fromTeamRule ? null : formatProbability(data.modelConfidence)
    };
  }

  async function scanUrl(url) {
    let endpoint;
    try { endpoint = new URL(`${API_BASE_URL}/scan`, window.location.origin); }
    catch { throw new Error("The scanning service address is not configured correctly."); }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
        credentials: "omit",
        referrerPolicy: "no-referrer",
        cache: "no-store"
      });
      if (response.status === 429) throw new Error("Too many scans right now. Wait a moment, then try again.");
      if (!response.ok) throw new Error(response.status >= 500 ? "The scanning service is temporarily unavailable. Try again later." : `The server could not process this scan (HTTP ${response.status}).`);
      let data;
      try { data = await response.json(); } catch { throw new Error("The server returned unreadable data. Please try again later."); }
      return normalizeResponse(data);
    } catch (cause) {
      if (cause.name === "AbortError") throw new Error("The scan took too long. Check your connection and try again.");
      if (cause instanceof TypeError) throw new Error("Could not reach the scanning service. Check your connection or try again later.");
      throw cause;
    } finally { window.clearTimeout(timeout); }
  }

  function renderResult(data) {
    const presentation = resultPresentation(data);
    result.dataset.verdict = presentation.verdict;
    resultHeading.textContent = presentation.title;
    verdictTag.textContent = presentation.verdict;
    summary.textContent = presentation.summary;
    normalizedUrl.textContent = data.normalizedUrl ? `Scanned address: ${data.normalizedUrl}` : "";
    const fromTeamRule = presentation.fromTeamRule;
    verdictSource.hidden = !fromTeamRule;
    verdictSource.textContent = presentation.sourceText
      ? `Team-configured demonstration rule; not an ML verdict. ${presentation.sourceText}` : "";
    modelDiagnostics.hidden = !fromTeamRule;
    if (fromTeamRule) {
      const modelLabel = data.modelPrediction || "unavailable";
      const probability = data.modelPhishingProbability;
      const probabilityText = formatProbability(probability) || "unavailable";
      modelDiagnostics.textContent = `Raw ML output: ${modelLabel}; phishing probability: ${probabilityText}.`;
    } else {
      const probabilityText = formatProbability(data.modelConfidence);
      modelDiagnostics.hidden = false;
      modelDiagnostics.textContent = probabilityText
        ? `Raw model prediction: ${data.modelPrediction || "unavailable"}; raw phishing score: ${formatProbability(data.modelPhishingProbability) || "unavailable"}.`
        : "Model-estimated confidence unavailable.";
    }
    estimateWrap.hidden = fromTeamRule || !formatProbability(data.modelConfidence);
    estimateValue.textContent = estimateWrap.hidden ? "" : formatProbability(data.modelConfidence);
    indicators.replaceChildren();
    for (const text of data.indicators) {
      const item = document.createElement("li");
      item.textContent = text;
      indicators.append(item);
    }
    indicatorsWrap.hidden = data.indicators.length === 0;
    result.hidden = false;
    status.textContent = "Scan complete. The prediction is an estimate and the scanner can make mistakes.";
    resultHeading.focus();
  }

  function showError(message) { error.textContent = message; error.hidden = false; input.setAttribute("aria-invalid", "true"); }
  function clearError() { error.textContent = ""; error.hidden = true; input.removeAttribute("aria-invalid"); }

  input.addEventListener("input", clearError);
  form.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();
    result.hidden = true;
    status.textContent = "";
    const validation = validateUrl(input.value);
    if (!validation.valid) { showError(validation.message); input.focus(); return; }
    button.disabled = true;
    button.querySelector("span:first-child").textContent = "Scanning…";
    status.textContent = "Checking the address. We will not open it.";
    try { renderResult(await scanUrl(validation.url)); }
    catch (cause) { status.textContent = cause.message || "Something went wrong. Please try again."; }
    finally { button.disabled = false; button.querySelector("span:first-child").textContent = "Scan URL"; }
  });

  scanAgain.addEventListener("click", () => {
    result.hidden = true;
    status.textContent = "Ready for another URL.";
    input.focus();
  });

  // Expose pure functions to Node's built-in test runner; no browser globals are needed there.
  if (typeof module !== "undefined" && module.exports) module.exports = { validateUrl, normalizeResponse, resultPresentation, formatProbability };
})();
