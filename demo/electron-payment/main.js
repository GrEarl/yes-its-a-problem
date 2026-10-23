"use strict";
const { app, BrowserWindow, ipcMain, net } = require("electron");
const fs = require("fs");
const path = require("path");

const EXPECTED = Object.freeze({
  merchant: "Karategata Demo Shop",
  account: "KBC-0001",
  amount: 1000,
  currency: "JPY"
});

function loadConfig() {
  const fallback = {
    apiUrl: "https://pay.v.lab.yes-its-a-problem.iamwonderingif.com",
    flavor: "hardened"
  };
  let cfg = { ...fallback };
  const candidates = [
    path.join(__dirname, "demo-config.json"),
    path.join(process.resourcesPath || "", "demo-config.json")
  ];
  for (const p of candidates) {
    try {
      if (p && fs.existsSync(p)) {
        cfg = { ...cfg, ...JSON.parse(fs.readFileSync(p, "utf8")) };
        break;
      }
    } catch (_) { /* keep fallback */ }
  }
  if (process.env.KBC_API_URL) cfg.apiUrl = process.env.KBC_API_URL;
  if (process.env.KBC_FLAVOR) cfg.flavor = process.env.KBC_FLAVOR;
  for (const arg of process.argv) {
    if (arg.startsWith("--kbc-api-url=")) cfg.apiUrl = arg.slice("--kbc-api-url=".length);
    if (arg.startsWith("--kbc-flavor=")) cfg.flavor = arg.slice("--kbc-flavor=".length);
  }
  return cfg;
}

const config = loadConfig();

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const res = await net.fetch(url, { cache: "no-store", signal: controller.signal, ...options });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch (_) { data = { raw: text.slice(0, 500) }; }
    return { ok: res.ok, status: res.status, data, url };
  } finally {
    clearTimeout(timer);
  }
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
}

app.whenReady().then(() => {
  ipcMain.handle("kbc:config", () => ({
    apiUrl: config.apiUrl,
    flavor: config.flavor,
    electron: process.versions.electron,
    chrome: process.versions.chrome,
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

  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  app.quit();
});
