"use strict";
const { app, BrowserWindow, ipcMain, net, shell } = require("electron");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("path");
const zlib = require("node:zlib");
const updatePolicy = require("./update-policy.js");

const EXPECTED = Object.freeze({
  merchant: "Karategata Demo Shop",
  account: "KBC-0001",
  amount: 1000
});

function loadApiUrl() {
  let apiUrl = "https://pay.v.lab.yes-its-a-problem.iamwonderingif.com";
  for (const arg of process.argv) {
    if (arg.startsWith("--kbc-api-url=")) apiUrl = arg.slice("--kbc-api-url=".length);
  }
  if (new URL(apiUrl).protocol !== "https:") throw new Error("KBC API URL must use HTTPS.");
  return apiUrl;
}

const config = { apiUrl: loadApiUrl() };

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const res = await net.fetch(url, { cache: "no-store", signal: controller.signal, ...options, redirect: "error" });
    const text = await res.text();
    let data, jsonValid = true;
    try { data = JSON.parse(text); } catch (_) { data = { raw: text.slice(0, 500) }; jsonValid = false; }
    return { ok: res.ok, status: res.status, data, jsonValid, url };
  } finally {
    clearTimeout(timer);
  }
}

// --- Update stage (Squirrel-style update check), lab only -------------------
// The update body is a valid Brotli lab marker; there is no exploit payload in
// this repository. Which Brotli copy decodes it is a build fact: an Electron
// binary links Chromium's //third_party/brotli only (Electron's GN patch drops
// Node's deps/brotli), so net.fetch, the renderer, fetch() and node:zlib all
// share one decoder, and its fix status tracks the Chromium version.
function loadUpdateConfig() {
  const env = process.env || {};
  const update = {
    flavor: null, stack: "node:zlib", artifact: "br",
    pinnedKeyPem: null, allowEncodings: ["identity"]
  };
  for (const arg of process.argv) {
    if (arg.startsWith("--kbc-update-flavor=")) update.flavor = arg.slice("--kbc-update-flavor=".length);
    if (arg.startsWith("--kbc-update-stack=")) update.stack = arg.slice("--kbc-update-stack=".length);
    if (arg.startsWith("--kbc-update-artifact=")) update.artifact = arg.slice("--kbc-update-artifact=".length);
    if (arg.startsWith("--kbc-update-allow-encoding=")) {
      update.allowEncodings = arg.slice("--kbc-update-allow-encoding=".length).split(",").filter(Boolean);
    }
    if (arg.startsWith("--kbc-update-pinned-key=")) {
      update.pinnedKeyPem = fs.readFileSync(arg.slice("--kbc-update-pinned-key=".length), "utf8");
    }
  }
  if (!update.flavor) {
    // The release workflow names the builds karategata-banking-demo-legacy /
    // -hardened; fall back to the environment, then to the demo default.
    let name = "";
    try { name = require("./package.json").name || ""; } catch (_) { name = ""; }
    if (name.endsWith("-hardened")) update.flavor = "hardened";
    else if (name.endsWith("-legacy")) update.flavor = "legacy";
    else update.flavor = env.KBC_UPDATE_FLAVOR || "legacy";
  }
  return update;
}

const updateConfig = loadUpdateConfig();

async function fetchRaw(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    return await net.fetch(url, { cache: "no-store", signal: controller.signal, redirect: "error", ...options });
  } finally {
    clearTimeout(timer);
  }
}

function updateTransport(base) {
  return {
    getFeed: async () => {
      const res = await fetchRaw(base + "/update/feed.json");
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch (_) { json = null; }
      return { status: res.status, json, text };
    },
    getArtifact: async (url) => {
      const res = await fetchRaw(base + url);
      return {
        status: res.status,
        contentEncoding: res.headers ? res.headers.get("content-encoding") : null,
        read: async () => new Uint8Array(await res.arrayBuffer())
      };
    }
  };
}

function createWindow() {
  const win = new BrowserWindow({
    width: 920,
    height: 760,
    minWidth: 720,
    minHeight: 620,
    backgroundColor: "#ffffff",
    title: "Karategata Banking",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.loadFile(path.join(__dirname, "renderer", "index.html"));

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://yes-its-a-problem.iamwonderingif.com")) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });
}

app.whenReady().then(() => {
  ipcMain.handle("kbc:config", () => ({
    apiUrl: config.apiUrl,
    expected: EXPECTED
  }));

  ipcMain.handle("kbc:quote", async () => {
    try {
      return await fetchJson(config.apiUrl.replace(/\/$/, "") + "/api/quote");
    } catch (e) {
      return { ok: false, error: String(e && e.message ? e.message : e) };
    }
  });

  ipcMain.handle("kbc:pay", async () => {
    try {
      return await fetchJson(config.apiUrl.replace(/\/$/, "") + "/api/pay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ demo: true, expected: EXPECTED })
      });
    } catch (e) {
      return { ok: false, error: String(e && e.message ? e.message : e) };
    }
  });

  ipcMain.handle("kbc:update", async () => {
    try {
      const base = config.apiUrl.replace(/\/$/, "");
      const evidence = await updatePolicy.runUpdateCheck({
        flavor: updateConfig.flavor,
        stack: updateConfig.stack,
        artifactName: updateConfig.artifact,
        pinnedKeyPem: updateConfig.pinnedKeyPem,
        allowEncodings: updateConfig.allowEncodings,
        transport: updateTransport(base),
        crypto,
        zlib,
        versions: process.versions || {}
      });
      if (typeof console !== "undefined") {
        console.log("kbc:update " + JSON.stringify({
          flavor: evidence.flavor, decision: evidence.decision, stack: evidence.stack,
          decoder_reached: evidence.decoder_reached, decode_calls: evidence.decode_calls,
          variant: evidence.variant, nonce: evidence.nonce
        }));
      }
      return evidence;
    } catch (e) {
      return { decision: "INCONCLUSIVE", error: String(e && e.message ? e.message : e) };
    }
  });

  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  app.quit();
});
