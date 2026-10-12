/* Backend setup: set API_BASE_URL to the backend origin and DEMO_MODE to false.
   The proposed contract is POST {API_BASE_URL}/scan with JSON {"url":"https://..."}.
   This endpoint/schema are integration placeholders, not confirmed backend behavior. */
(() => {
  "use strict";

  const API_BASE_URL = "";
  const DEMO_MODE = true;
  const REQUEST_TIMEOUT_MS = 10000;
  const ALLOWED_VERDICTS = new Set(["phishing", "malicious", "legitimate", "uncertain"]);

  // Keep the pure URL/response helpers usable in Node's built-in test runner.
  if (typeof document === "undefined") {
    if (typeof module !== "undefined" && module.exports) module.exports = { validateUrl, normalizeResponse };
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
  const confidenceWrap = document.querySelector("#confidence-wrap");
  const confidenceValue = document.querySelector("#confidence-value");
  const indicatorsWrap = document.querySelector("#indicators-wrap");
  const indicators = document.querySelector("#indicators");
  const scanAgain = document.querySelector("#scan-again");
  const modeLabel = document.querySelector("#mode-label");

  modeLabel.textContent = DEMO_MODE ? "DEMO MODE · illustrative responses" : "";

  function validateUrl(value, options = {}) {
    const text = String(value ?? "").trim();
    if (!text) return { valid: false, message: "Enter a URL to check." };
    if (/\s/.test(text)) return { valid: false, message: "Remove spaces from the URL and try again." };
    let parsed;
    try { parsed = new URL(text); } catch { return { valid: false, message: "Enter a complete URL, such as https://example.com." }; }
    if (!["http:", "https:"].includes(parsed.protocol)) return { valid: false, message: "Only http:// and https:// web addresses are supported." };
    if (parsed.username || parsed.password) return { valid: false, message: "URLs containing a username or password are not accepted." };
    const localHost = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(parsed.hostname);
    if (!parsed.hostname || (!parsed.hostname.includes(".") && !localHost)) return { valid: false, message: "Enter a complete website address, such as https://example.com." };
    if (options.requireHttps !== false && parsed.protocol !== "https:" && !localHost) return { valid: false, message: "Use an https:// address. Plain HTTP is allowed only for local development." };
    return { valid: true, url: parsed.href };
  }

  function normalizeResponse(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("The server returned an unexpected response. Please try again later.");
    const rawVerdict = String(data.verdict ?? data.label ?? "").toLowerCase();
    const verdict = rawVerdict === "safe" ? "legitimate" : rawVerdict === "unknown" ? "uncertain" : rawVerdict;
    if (!ALLOWED_VERDICTS.has(verdict)) throw new Error("The server response did not include a recognized verdict.");
    const confidenceNumber = typeof data.confidence === "number" ? data.confidence : null;
    const confidence = confidenceNumber !== null && Number.isFinite(confidenceNumber) && confidenceNumber >= 0 && confidenceNumber <= 1
      ? confidenceNumber <= 1 ? Math.round(confidenceNumber * 100) : null : null;
    // A backend may send a 0–100 confidence number; accept it only if explicitly in range.
    const normalizedConfidence = confidenceNumber !== null && confidenceNumber > 1 && confidenceNumber <= 100 ? Math.round(confidenceNumber) : confidence;
    const list = Array.isArray(data.indicators) ? data.indicators : Array.isArray(data.signals) ? data.signals : [];
    return {
      verdict,
      summary: typeof data.summary === "string" ? data.summary.slice(0, 1000) : "The scan completed. Review the result with care.",
      confidence: normalizedConfidence,
      indicators: list.filter(item => typeof item === "string").slice(0, 12).map(item => item.slice(0, 240))
    };
  }

  async function scanUrl(url) {
    if (DEMO_MODE) {
      await new Promise(resolve => window.setTimeout(resolve, 550));
      // Explicitly illustrative only; never represents a real threat-intelligence scan.
      return normalizeResponse({ verdict: "uncertain", summary: "Demo response only. No real security analysis was performed. Connect the backend to scan URLs.", indicators: ["Illustrative demo result"] });
    }
    if (!API_BASE_URL) throw new Error("The scanning service has not been configured yet.");
    let endpoint;
    try { endpoint = new URL("scan", API_BASE_URL.endsWith("/") ? API_BASE_URL : `${API_BASE_URL}/`); }
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
    result.dataset.verdict = data.verdict;
    const titles = { phishing: "Likely phishing", malicious: "Potentially malicious", legitimate: "No threat detected", uncertain: "Unable to determine" };
    resultHeading.textContent = titles[data.verdict];
    verdictTag.textContent = data.verdict;
    summary.textContent = data.summary;
    confidenceWrap.hidden = data.confidence === null;
    confidenceValue.textContent = data.confidence === null ? "" : `${data.confidence}%`;
    indicators.replaceChildren();
    for (const text of data.indicators) {
      const item = document.createElement("li");
      item.textContent = text;
      indicators.append(item);
    }
    indicatorsWrap.hidden = data.indicators.length === 0;
    result.hidden = false;
    status.textContent = "Scan complete. Review the result below.";
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
    const validation = validateUrl(input.value, { requireHttps: true });
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
  if (typeof module !== "undefined" && module.exports) module.exports = { validateUrl, normalizeResponse };
})();
