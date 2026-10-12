const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { validateUrl, normalizeResponse, formatProbability, resultPresentation } = require("./script.js");

test("normalizes the Flask API response and predicted-class confidence", () => {
  assert.deepEqual(normalizeResponse({
    prediction: "phishing",
    verdict: "phishing",
    confidence: 0.91,
    summary: "Model estimate.",
    indicators: ["Long URL"],
  }), {
    verdict: "phishing",
    summary: "Model estimate.",
    normalizedUrl: "",
    indicators: ["Long URL"],
    verdictSource: "ml_model",
    policyOverride: false,
    policyReason: "",
    modelPrediction: "phishing",
    modelPhishingProbability: null,
    modelConfidence: 0.91,
  });
});

test("rejects malformed responses and does not invent optional values", () => {
  assert.throws(() => normalizeResponse(null), /unexpected response/);
  assert.throws(() => normalizeResponse({ prediction: "uncertain" }), /recognized verdict/);
  assert.deepEqual(normalizeResponse({ prediction: "legitimate" }), {
    verdict: "legitimate", normalizedUrl: "", summary: "", indicators: [],
    verdictSource: "ml_model", policyOverride: false, policyReason: "",
    modelPrediction: "legitimate", modelPhishingProbability: null,
    modelConfidence: null,
  });
});

test("uses the final team-rule verdict and keeps raw model diagnostics separate", () => {
  const result = normalizeResponse({
    prediction: "legitimate",
    model_prediction: "legitimate",
    verdict: "phishing",
    confidence: null,
    phishing_probability: 0.03,
    model_phishing_probability: 0.03,
    verdict_source: "team_rule",
    policy_override: true,
    policy_reason: "Team demonstration policy matched.",
  });
  assert.equal(result.verdict, "phishing");
  assert.equal(result.verdictSource, "team_rule");
  assert.equal(result.policyOverride, true);
  assert.equal(result.modelPrediction, "legitimate");
  assert.equal(result.modelPhishingProbability, 0.03);
  assert.equal(result.modelConfidence, null);
});

test("validates submitted URLs", () => {
  assert.equal(validateUrl("https://example.com").valid, true);
  assert.equal(validateUrl("https://www.wikipedia.org").url, "https://www.wikipedia.org");
  assert.equal(validateUrl("example.org/path").url, "https://example.org/path");
  assert.equal(validateUrl("http://example.org").url, "http://example.org");
  assert.equal(validateUrl("ftp://example.com").valid, false);
  assert.equal(validateUrl("javascript:alert(1)").valid, false);
  assert.equal(validateUrl("https://user:pass@example.org").valid, false);
  assert.equal(validateUrl("https://example.org:70000").valid, false);
  assert.equal(validateUrl("https://example.org/a b").valid, false);
  assert.equal(validateUrl(" https://example.org ").url, "https://example.org");
});

test("rejects non-binary successful verdicts and reports scores without 0 or 100 percent", () => {
  assert.throws(() => normalizeResponse({ verdict: "inconclusive", prediction: "phishing" }), /recognized verdict/);
  assert.equal(formatProbability(0), "<0.01%");
  assert.equal(formatProbability(1), ">99.99%");
  assert.equal(formatProbability(0.999999), ">99.99%");
  assert.equal(formatProbability(0.000001), "<0.01%");
  assert.equal(formatProbability(null), null);
});

test("renders the exact Wikipedia API response as legitimate using verdict precedence", () => {
  const wikipediaResponse = {
    model_mode: "ml",
    phishing_probability: 0.003264683236725241,
    prediction: "legitimate",
    summary: "The model did not classify this URL as phishing. This estimate is not a guarantee that the URL is safe.",
    url: "https://www.wikipedia.org",
    verdict: "legitimate",
  };
  const normalized = normalizeResponse(wikipediaResponse);
  const view = resultPresentation(normalized);
  assert.equal(normalized.verdict, "legitimate");
  assert.equal(view.title, "LEGITIMATE");
  assert.equal(view.verdict, "legitimate");
  assert.equal(view.probabilityText, "99.67%");
  assert.match(view.summary, /not a guarantee/i);
});

test("a valid final verdict is not overridden by contradictory model fields", () => {
  const normalized = normalizeResponse({
    verdict: "legitimate",
    prediction: "phishing",
    phishing_probability: 1,
    model_mode: "ml",
  });
  assert.equal(resultPresentation(normalized).title, "LEGITIMATE");
  assert.equal(normalized.modelPrediction, "phishing");
});

test("renders binary verdicts and a team-rule override distinctly", () => {
  const phishing = resultPresentation(normalizeResponse({ verdict: "phishing", prediction: "phishing" }));
  const override = resultPresentation(normalizeResponse({
    verdict: "phishing",
    prediction: "legitimate",
    verdict_source: "team_rule",
    policy_override: true,
    policy_reason: "Matched the configured example.com demonstration rule.",
    phishing_probability: 0.02,
  }));
  assert.equal(phishing.title, "PHISHING");
  assert.equal(phishing.fromTeamRule, false);
  assert.throws(() => resultPresentation({ verdict: "inconclusive" }), /recognized verdict/);
  assert.equal(override.title, "PHISHING");
  assert.equal(override.fromTeamRule, true);
  assert.match(override.sourceText, /example.com demonstration rule/);
  assert.equal(override.probabilityText, null);
});

test("rejects absent or malformed verdicts instead of defaulting to phishing", () => {
  assert.throws(() => normalizeResponse({}), /recognized verdict/);
  assert.throws(() => normalizeResponse({ verdict: "unexpected", prediction: "phishing" }), /recognized verdict/);
  assert.throws(() => normalizeResponse({ verdict: "safe", prediction: "phishing" }), /recognized verdict/);
  assert.throws(() => normalizeResponse({ verdict: null, prediction: "phishing" }), /recognized verdict/);
  assert.throws(() => resultPresentation({}), /recognized verdict/);
});

test("keeps legacy fallback only when no final verdict exists", () => {
  assert.equal(normalizeResponse({ prediction: "safe" }).verdict, "legitimate");
  assert.throws(() => normalizeResponse({ label: "unknown" }), /recognized verdict/);
});

test("does not contain a demo response path", () => {
  const source = fs.readFileSync(path.join(__dirname, "script.js"), "utf8");
  assert.doesNotMatch(source, /DEMO_MODE|Illustrative demo result|Demo response only/);
});

test("loads cache-busted assets and uses verdict-specific CSS classes", () => {
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "style.css"), "utf8");
  const script = fs.readFileSync(path.join(__dirname, "script.js"), "utf8");
  assert.match(html, /script\.js\?v=binary-verdict-2/);
  assert.match(html, /model-estimated confidence/i);
  assert.match(html, /not guarantees of safety/i);
  assert.doesNotMatch(css, /data-verdict="inconclusive"/);
  assert.equal((script.match(/form\.addEventListener\("submit"/g) || []).length, 1);
});
