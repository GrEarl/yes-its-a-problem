"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

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

function main(apiUrl, fetch) {
  const handlers = new Map();
  const electron = {
    app: { whenReady: () => ({ then: (fn) => fn() }), on() {}, quit() {} },
    BrowserWindow: class {
      constructor() { this.webContents = { setWindowOpenHandler() {} }; }
      loadFile() {}
    },
    ipcMain: { handle: (name, fn) => handlers.set(name, fn) }, net: { fetch }, shell: {}
  };
  vm.runInNewContext(source("main.js"), {
    require: (name) => name === "electron" ? electron : require(name),
    process: { argv: ["electron", ".", "--kbc-api-url=" + apiUrl] },
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
  console.log("Electron response checks passed (stubbed IPC/network; no TLS connection).");
})().catch((error) => { console.error(error); process.exitCode = 1; });
