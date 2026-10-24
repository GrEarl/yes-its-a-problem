"use strict";
// Run: node docs/test.js. No network, browser, or trust-store changes.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const scripts = ["config", "i18n", "app"].map(name =>
  fs.readFileSync(path.join(__dirname, name + ".js"), "utf8"));
const fingerprint = "a".repeat(64);

function page({ query = "?lang=en", saved = null, language = "en", denied = false } = {}) {
  const elements = [...html.matchAll(/<[a-z0-9-]+\b([^>]*)>/gi)].map(([, attrs]) => {
    const getAttribute = name => (attrs.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`)) || [])[1] || null;
    const classes = new Set((getAttribute("class") || "").split(/\s+/));
    return { id: getAttribute("id"), getAttribute, textContent: "", disabled: false, listeners: {},
      addEventListener(name, fn) { this.listeners[name] = fn; },
      classList: { add: name => classes.add(name), remove: name => classes.delete(name),
        contains: name => classes.has(name), toggle(name, on) { on ? classes.add(name) : classes.delete(name); } } };
  });
  const elementsById = Object.fromEntries(elements.filter(el => el.id).map(el => [el.id, el]));
  const events = {}, timers = new Set();
  let request = async () => { throw new Error("offline"); };
  const context = { URLSearchParams, AbortController, crypto,
    setTimeout(fn) { timers.add(fn); return fn; }, clearTimeout: fn => timers.delete(fn),
    location: { search: query }, navigator: { languages: [language] },
    localStorage: { getItem() { if (denied) throw new Error("storage denied"); return saved; },
      setItem() { if (denied) throw new Error("storage denied"); } },
    document: { documentElement: {}, getElementById: id => elementsById[id], querySelectorAll(selector) {
      if (selector === "[data-i18n]") return elements.filter(el => el.getAttribute("data-i18n"));
      if (selector === ".lang-btn") return elements.filter(el => el.getAttribute("class") === "lang-btn");
      if (selector === "[data-releases]") return [];
      throw new Error(selector);
    } }, addEventListener: (name, fn) => { events[name] = fn; },
    fetch(url, options) {
      assert.equal(new URL(url).protocol, "https:");
      assert.equal(options.cache, "no-store");
      assert.equal(options.credentials, "omit");
      assert.equal(options.redirect, "error");
      return request(url, options);
    } };
  context.window = context;
  vm.createContext(context);
  scripts.forEach(script => vm.runInContext(script, context));
  events.DOMContentLoaded();
  return { context, elements: elementsById, timers,
    request: fn => { request = fn; }, click: id => elementsById[id].listeners.click(),
    t: key => context.YIP_I18N.t(key) };
}

const response = (data, ok = true) => ({ ok, json: async () => data });
function payload(url, status) {
  const target = new URL(url);
  return target.pathname === "/probe"
    ? { path: status, host: target.host, token: target.searchParams.get("token") }
    : { tls: status, host: target.host, leaf_sha256: fingerprint, issuer_spki_sha256: fingerprint };
}

(async () => {
  for (const language of ["en", "ja"]) {
    for (const dns of ["true", "fake", "unknown"]) for (const tls of ["other", "forged", "unknown"]) {
      const p = page({ query: "?lang=" + language });
      p.request(async url => response(payload(url, new URL(url).pathname === "/probe" ? dns : tls)));
      await p.click("dns-btn");
      assert.equal(p.elements["verdict-summary"].textContent, p.t("verdictNotRun"));
      await p.click("tls-btn");
      assert.equal(p.elements["dns-result"].textContent, p.t({ true: "dnsSafe", fake: "dnsBad", unknown: "dnsUnknown" }[dns]));
      assert.equal(p.elements["tls-result"].textContent, p.t({ other: "tlsGood", forged: "tlsBad", unknown: "tlsUnknown" }[tls]));
      assert(!/^SAFE|^安全/.test(p.elements["verdict-summary"].textContent));
      assert.equal(p.timers.size, 0);
    }
  }

  for (const kind of ["dns", "tls"]) {
    const p = page();
    p.request(async url => response(payload(url, kind === "dns" ? "true" : "other")));
    await p.click(kind + "-btn");
    let complete, currentUrl, count = 0;
    p.request(url => { currentUrl = url; count++; return new Promise(resolve => { complete = resolve; }); });
    const running = p.click(kind + "-btn");
    for (const language of ["ja", "en"]) {
      p.click("lang-" + language);
      assert.equal(p.elements[kind + "-result"].textContent, p.t("checking"));
      assert.equal(p.elements[kind + "-btn"].textContent, p.t("checking"));
      assert(p.elements["dns-btn"].disabled && p.elements["tls-btn"].disabled);
      assert(p.elements.verdict.classList.contains("hidden"));
    }
    await p.click((kind === "dns" ? "tls" : "dns") + "-btn");
    assert.equal(count, 1);
    complete(response(payload(currentUrl, kind === "dns" ? "fake" : "forged")));
    await running;
    assert.equal(p.elements[kind + "-result"].textContent, p.t(kind === "dns" ? "dnsBad" : "tlsBad"));
    assert(!p.elements["dns-btn"].disabled && !p.elements["tls-btn"].disabled);
    assert(!p.elements.verdict.classList.contains("hidden"));

    const invalid = [{ host: "wrong.test" }, { host: undefined }, kind === "dns" ? { token: "wrong" } : { leaf_sha256: "invalid" },
      kind === "dns" ? { path: undefined } : { tls: undefined }, kind === "dns" ? { path: "unexpected" } : { tls: "valid" }];
    if (kind === "tls") invalid.push({ leaf_sha256: undefined }, { leaf_sha256: [fingerprint] },
      { leaf_sha256: fingerprint.toUpperCase() }, { issuer_spki_sha256: undefined }, { issuer_spki_sha256: [fingerprint] });
    for (const changes of invalid) {
      p.request(async url => response({ ...payload(url, kind === "dns" ? "fake" : "forged"), ...changes }));
      await p.click(kind + "-btn");
      assert.equal(p.elements[kind + "-result"].textContent, p.t(kind + "Unknown"));
    }
    for (const request of [async () => response(null), async url => response(payload(url, "forged"), false),
      async () => ({ ok: true, json: async () => { throw new SyntaxError("bad JSON"); } }),
      async () => { throw new Error("network failure"); }]) {
      p.request(request);
      await p.click(kind + "-btn");
      assert.equal(p.elements[kind + "-result"].textContent, p.t(kind + "Unknown"));
    }
    p.request((url, { signal }) => new Promise((resolve, reject) => signal.addEventListener("abort", () => reject(new Error("aborted")))));
    const timeout = p.click(kind + "-btn");
    [...p.timers].forEach(fn => fn());
    await timeout;
    assert.equal(p.elements[kind + "-result"].textContent, p.t(kind + "Unknown"));
    assert.equal(p.timers.size, 0);
  }

  for (const [query, language, expected] of [["?lang=ja", "en", "ja"], ["?lang=en", "ja", "en"], ["", "ja", "ja"]]) {
    assert.equal(page({ query, language, denied: true }).context.document.documentElement.lang, expected);
  }
  assert.equal(page({ query: "", saved: "ja" }).context.document.documentElement.lang, "ja");
  assert.equal(page({ query: "?lang=en", saved: "ja" }).context.document.documentElement.lang, "en");
  const english = page();
  for (const [, key, text] of html.matchAll(/data-i18n="([^"]+)"[^>]*>([^<]*)</g)) {
    assert.equal(text, english.t(key), "Static English text: " + key);
    english.context.YIP_I18N.setLang("ja");
    assert.notEqual(english.t(key), key, "Japanese translation: " + key);
    english.context.YIP_I18N.setLang("en");
  }
  console.log("PASS: 18 result combinations, response contract failures, pending/language behavior, timeouts, storage fallback, and static translations (no network).");
})().catch(error => { console.error(error); process.exitCode = 1; });
