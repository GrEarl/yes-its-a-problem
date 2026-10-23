"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const zlib = require("node:zlib");
const updatePolicy = require("./update-policy.js");

const source = (file) => fs.readFileSync(path.join(__dirname, file), "utf8");
const expected = { merchant: "Karategata Demo Shop", account: "KBC-0001", amount: 1000, currency: "JPY" };
const ok = (data) => ({ ok: true, status: 200, jsonValid: true, data });
const certError = { ok: false, error: "net::ERR_CERT_AUTHORITY_INVALID" };

// Minimal DOM and IPC stand-ins: execute the real renderer without Electron.
async function renderer(quote, pay = async () => ok({ ...expected, status: "paid" })) {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) {
      const classes = new Set(["received", "safe", "danger"].includes(id) ? ["hidden"] : []);
      elements.set(id, {
        id, textContent: "", className: "", disabled: id === "pay-btn", events: {},
        classList: {
          toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
          contains(name) { return classes.has(name); }
        },
        addEventListener(name, fn) { this.events[name] = fn; }
      });
    }
    return elements.get(id);
  };
  const window = {
    kbc: { config: async () => ({ expected }), quote, pay },
    addEventListener(name, fn) { this[name] = fn; }
  };
  const context = vm.createContext({
    window, document: { getElementById: get, querySelectorAll: () => [], documentElement: {} },
    localStorage: { getItem: () => null, setItem() {} }, navigator: { language: "en" },
    console: { error() {} }
  });
  vm.runInContext(source("renderer/i18n.js"), context);
  vm.runInContext(source("renderer/app.js"), context);
  await window.DOMContentLoaded();
  return {
    get,
    hidden: (id) => get(id).classList.contains("hidden"),
    click: (id) => get(id).disabled ? undefined : get(id).events.click()
  };
}

function main(apiUrl, fetch, options = {}) {
  const handlers = new Map();
  const electron = {
    app: { whenReady: () => ({ then: (fn) => fn() }), on() {}, quit() {} },
    BrowserWindow: class {
      constructor() { this.webContents = { setWindowOpenHandler() {} }; }
      loadFile() {}
    },
    ipcMain: { handle: (name, fn) => handlers.set(name, fn) }, net: { fetch }, shell: {}
  };
  const requireStub = (name) => {
    if (name === "electron") return electron;
    if (name === "node:zlib" && options.zlib) return options.zlib;
    return require(name);
  };
  vm.runInNewContext(source("main.js"), {
    require: requireStub,
    process: {
      argv: ["electron", ".", "--kbc-api-url=" + apiUrl, ...(options.args || [])],
      env: options.env || {},
      versions: options.versions || {}
    },
    __dirname, URL, AbortController, setTimeout, clearTimeout
  });
  return handlers;
}

(async () => {
  for (const failure of [certError, { ok: false, error: "net::ERR_CONNECTION_REFUSED" }, ok({})]) {
    let calls = 0;
    const ui = await renderer(async () => ++calls === 1 ? ok(expected) : failure);
    await ui.click("quote-btn");
    await ui.click("quote-btn");
    await ui.click("lang-ja");
    assert(ui.hidden("received"), "language changes must not restore a failed quote");
    assert.equal(ui.get("pay-btn").disabled, true);
    assert.equal(ui.hidden("safe"), failure !== certError);
  }

  const paid = { ...expected, account: "ATTACKER-9999", amount: 999999, status: "paid", receipt: "test" };
  const payment = await renderer(async () => ok(expected), async () => ok(paid));
  await payment.click("quote-btn");
  await payment.click("pay-btn");
  await payment.click("lang-ja");
  assert.equal(payment.get("recv-account").textContent, paid.account);
  assert.equal(payment.hidden("danger"), false);

  for (const data of [{ ...expected, currency: "USD" }, { ...expected, currency: undefined }, { ...expected, amount: null }]) {
    const ui = await renderer(async () => ok(data));
    await ui.click("quote-btn");
    assert(ui.hidden("received"), "invalid quote data must be inconclusive");
    assert.equal(ui.get("pay-btn").disabled, true);
    assert(ui.get("status").textContent.startsWith("INCONCLUSIVE:"));
  }
  for (const result of [certError, ok({ ...expected, status: "declined" }), ok(expected), ok({ ...paid, currency: "USD" })]) {
    const ui = await renderer(async () => ok(expected), async () => result);
    await ui.click("quote-btn");
    await ui.click("pay-btn");
    await ui.click("lang-ja");
    assert(ui.hidden("received"), "failed payments must discard the earlier quote");
    assert.equal(ui.get("pay-btn").disabled, true);
    assert.equal(ui.hidden("safe"), result !== certError);
  }

  let resolvePay, quoteCalls = 0;
  const pending = new Promise((resolve) => { resolvePay = resolve; });
  const busy = await renderer(async () => { quoteCalls++; return ok(expected); }, async () => pending);
  await busy.click("quote-btn");
  const request = busy.click("pay-btn");
  assert.equal(busy.get("quote-btn").disabled, true);
  assert.equal(busy.get("pay-btn").disabled, true);
  await busy.click("quote-btn");
  await busy.click("lang-ja");
  assert.equal(quoteCalls, 1, "a payment must prevent another quote request");
  assert(busy.hidden("received"));
  resolvePay(ok(paid));
  await request;
  assert.equal(busy.get("quote-btn").disabled, false);
  assert.equal(busy.get("pay-btn").disabled, false);

  assert.throws(() => main("http://127.0.0.1:9443", () => assert.fail("HTTP must not be fetched")), /must use HTTPS/);
  const requests = [];
  const handlers = main("https://pay.example.test:9443", async (url, options) => {
    requests.push({ url, options });
    return { ok: true, status: 200, text: async () => JSON.stringify(expected) };
  });
  for (const channel of ["kbc:quote", "kbc:pay"]) assert.equal((await handlers.get(channel)()).ok, true);
  assert.equal(requests[0].url, "https://pay.example.test:9443/api/quote");
  assert.equal(requests[1].options.method, "POST");
  for (const request of requests) assert.equal(request.options.redirect, "error");
  // --- Update stage: Brotli decode step (valid lab markers only) -----------
  // No malformed stream and no memory-corruption payload exists in this repo;
  // the artifacts below are valid Brotli compressions of marker documents.
  const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
  const nonce = "test-nonce-2026-10-27";
  const genuineDoc = JSON.stringify({ artifact: "LAB-BROTLI-ARTIFACT", variant: "genuine", nonce });
  const attackerDoc = JSON.stringify({ artifact: "LAB-BROTLI-ARTIFACT", variant: "attacker", nonce });
  const genuineBody = zlib.brotliCompressSync(Buffer.from(genuineDoc));
  const attackerBody = zlib.brotliCompressSync(Buffer.from(attackerDoc));
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pinnedKeyPath = path.join(os.tmpdir(), "kbc-update-test-pinned-key.pem");
  fs.writeFileSync(pinnedKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }));
  const signBytes = (buf) => crypto.createSign("sha256").update(buf).sign(keys.privateKey).toString("base64");
  const feed = {
    name: "demo-lib", version: "0.0.2", marker: "LAB-BROTLI-ARTIFACT",
    artifacts: {
      br: { url: "/update_body.br", encoding: "br", sha256: sha256(genuineBody), signature: signBytes(genuineBody) },
      plain: { url: "/update_body.json", encoding: "identity",
               sha256: sha256(Buffer.from(genuineDoc)), signature: signBytes(Buffer.from(genuineDoc)) }
    }
  };

  // net.fetch stand-in. On the "chromium" path the br body comes back already
  // decoded (that is what Chromium's net stack does); on the "node:zlib" path
  // the app receives the compressed bytes and decodes them itself.
  function updateFetch(state) {
    return async (url) => {
      if (url.endsWith("/update/feed.json")) {
        state.feedCalls += 1;
        return { status: 200, text: async () => JSON.stringify(feed) };
      }
      state.artifactCalls += 1;
      const plain = url.endsWith(".json");
      const doc = state.variant === "attacker" ? attackerDoc : genuineDoc;
      const raw = plain ? Buffer.from(doc)
        : (state.variant === "attacker" ? attackerBody : genuineBody);
      const delivered = (!plain && state.stack === "chromium" && state.contentEncoding === "br")
        ? Buffer.from(doc) : raw;
      return {
        status: 200,
        headers: { get: (name) => (name.toLowerCase() === "content-encoding" ? state.contentEncoding : null) },
        arrayBuffer: async () => {
          state.reads += 1;
          return delivered.buffer.slice(delivered.byteOffset, delivered.byteOffset + delivered.byteLength);
        },
        text: async () => delivered.toString("utf8")
      };
    };
  }

  function state(overrides) {
    return Object.assign({
      variant: "genuine", contentEncoding: null, stack: "node:zlib",
      decodeCalls: 0, reads: 0, feedCalls: 0, artifactCalls: 0
    }, overrides);
  }

  function zlibSpy(s) {
    return Object.assign({}, zlib, {
      createBrotliDecompress: (...args) => { s.decodeCalls += 1; return zlib.createBrotliDecompress(...args); }
    });
  }

  const api = "https://pay.example.test:9443";
  const pinArg = "--kbc-update-pinned-key=" + pinnedKeyPath;

  // Pair B - verify-before-decode with a PINNED key. Identical attacker body on
  // the same request path: the legacy flavor hands it to the decoder first, the
  // hardened flavor rejects it before any decoder call. THIS pair is the
  // legacy-vs-hardened divergence of this stage.
  {
    const legacyState = state({ variant: "attacker" });
    const legacy = main(api, updateFetch(legacyState), {
      args: [pinArg, "--kbc-update-flavor=legacy"], zlib: zlibSpy(legacyState)
    });
    const legacyEvidence = await legacy.get("kbc:update")();
    const hardenedState = state({ variant: "attacker" });
    const hardened = main(api, updateFetch(hardenedState), {
      args: [pinArg, "--kbc-update-flavor=hardened"], zlib: zlibSpy(hardenedState)
    });
    const hardenedEvidence = await hardened.get("kbc:update")();

    assert.equal(legacyEvidence.decision, "DECODED", "legacy must decode the attacker body");
    assert.equal(legacyEvidence.decode_calls, 1);
    assert.equal(legacyState.decodeCalls, 1, "legacy must invoke the Brotli decoder exactly once");
    assert.equal(legacyEvidence.variant, "attacker");
    assert.equal(legacyEvidence.marker, "LAB-BROTLI-ARTIFACT");
    assert.equal(legacyEvidence.nonce, nonce);
    assert.equal(hardenedEvidence.decision, "SIG_REJECTED", "hardened must reject before decode");
    assert.equal(hardenedEvidence.decode_calls, 0);
    assert.equal(hardenedState.decodeCalls, 0, "hardened must never invoke the Brotli decoder");
    assert.equal(hardenedEvidence.decoder_reached, false);
    console.log("Divergence assertion (Pair B): same attacker body -> legacy DECODED " +
      "(decode_calls=1) vs hardened SIG_REJECTED (decode_calls=0).");
  }

  // Positive control: the hardened flavor accepts the genuine signed body and
  // decodes it - the rejection above is the signature check, not breakage.
  {
    const s = state({ variant: "genuine" });
    const handlers = main(api, updateFetch(s), {
      args: [pinArg, "--kbc-update-flavor=hardened"], zlib: zlibSpy(s)
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "DECODED");
    assert.equal(evidence.variant, "genuine");
    assert.equal(s.decodeCalls, 1);
  }

  // Fail closed: hardened without a pinned key refuses to proceed at all.
  {
    const s = state({ variant: "attacker" });
    const handlers = main(api, updateFetch(s), {
      args: ["--kbc-update-flavor=hardened"], zlib: zlibSpy(s)
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "SIG_REJECTED");
    assert.match(evidence.reason, /pinned publisher key/);
    assert.equal(s.decodeCalls, 0);
  }

  // Pair C - content-encoding policy: the signed genuine body arrives with
  // Content-Encoding: br; hardened refuses it before the body is consumed.
  {
    const s = state({ variant: "genuine", stack: "chromium", contentEncoding: "br" });
    const handlers = main(api, updateFetch(s), {
      args: [pinArg, "--kbc-update-flavor=hardened", "--kbc-update-stack=chromium",
             "--kbc-update-allow-encoding=identity"],
      zlib: zlibSpy(s)
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "ENCODING_REJECTED");
    assert.equal(s.reads, 0, "the br response body must never be consumed");
    assert.equal(s.decodeCalls, 0);
    console.log("Pair C assertion: Content-Encoding: br -> hardened ENCODING_REJECTED " +
      "with 0 body reads and 0 decoder calls.");
  }

  // The same path on the chromium delivery: legacy consumes the body and the
  // decoder (inside the HTTP stack) is reached; the app reports the marker.
  {
    const s = state({ variant: "attacker", stack: "chromium", contentEncoding: "br" });
    const handlers = main(api, updateFetch(s), {
      args: [pinArg, "--kbc-update-flavor=legacy", "--kbc-update-stack=chromium"], zlib: zlibSpy(s)
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "DECODED");
    assert.equal(evidence.decoder_reached, true);
    assert.equal(evidence.variant, "attacker");
    assert.equal(s.reads, 1);
  }

  // Negative control (required): the plain, uncompressed body succeeds on the
  // same request path in BOTH flavors, with the same key and URL.
  for (const flavor of ["legacy", "hardened"]) {
    const s = state({});
    const handlers = main(api, updateFetch(s), {
      args: [pinArg, "--kbc-update-flavor=" + flavor, "--kbc-update-artifact=plain"], zlib: zlibSpy(s)
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "ACCEPTED", flavor + " must accept the plain body");
    assert.equal(s.decodeCalls, 0, "the plain body needs no decoder");
    assert.equal(s.reads, 1);
  }
  console.log("Negative control: the plain body is ACCEPTED in both flavors on the same request path.");

  // Pair A1 - decoder identity. The fingerprint keys on the CHROMIUM version
  // (an Electron binary links Chromium's //third_party/brotli only), never on
  // the bundled Node version: a Node-version key would wrongly label the
  // hardened build vulnerable.
  assert.equal(updatePolicy.decoderFingerprint({ chrome: "156.0.8078.48", node: "24.22.0" }, "chromium").decoder_status,
    "fixed", "Chromium 156 must read as fixed even though its Node 24.22.0 is below baseline");
  assert.equal(updatePolicy.decoderFingerprint({ chrome: "136.0.7103.177", node: "22.19.0" }, "chromium").decoder_status,
    "vulnerable");
  assert.equal(updatePolicy.decoderFingerprint({ chrome: "147.0.7727.137" }, "chromium").decoder_status,
    "vulnerable", "Chromium 147 is still pre-fix; the boundary is 148");
  assert.equal(updatePolicy.decoderFingerprint({ chrome: "148.0.7778.96" }, "chromium").decoder_status, "fixed");
  assert.equal(updatePolicy.decoderFingerprint({ node: "v24.22.0" }, "node:zlib").decoder_status,
    "vulnerable", "plain Node keys on the Node line");
  assert.equal(updatePolicy.decoderFingerprint({ node: "v26.12.1" }, "node:zlib").decoder_status, "fixed");
  {
    const s = state({ variant: "genuine" });
    const handlers = main(api, updateFetch(s), {
      args: [pinArg, "--kbc-update-flavor=legacy"], zlib: zlibSpy(s),
      versions: { node: "24.22.0", chrome: "156.0.8078.48", electron: "45.0.0" }
    });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decoder.linkage, "electron");
    assert.equal(evidence.decoder.decoder_status, "fixed");
  }

  // Transport rejection is classified as its own decision marker.
  {
    const failing = async () => { throw new Error("net::ERR_CERT_AUTHORITY_INVALID"); };
    const handlers = main(api, failing, { args: [pinArg, "--kbc-update-flavor=legacy"], zlib });
    const evidence = await handlers.get("kbc:update")();
    assert.equal(evidence.decision, "TLS_REJECTED");
  }

  console.log("Electron response checks passed (stubbed IPC/network; no TLS connection).");
  console.log("Update-stage checks passed: legacy decodes the attacker body, hardened rejects before decode.");
})().catch((error) => { console.error(error); process.exitCode = 1; });
