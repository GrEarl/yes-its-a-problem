"use strict";
(function () {
  const cfg = window.YIP_CONFIG || {};
  const t = (k) => (window.YIP_I18N ? window.YIP_I18N.t(k) : k);
  const $ = (id) => document.getElementById(id);
  const state = { dns: null, tls: null };
  let checking = null;

  function setText(id, text, cls) {
    const el = $(id);
    el.textContent = text || "";
    el.className = "result" + (cls ? " " + cls : "");
  }

  function isSha256(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  }

  function renderAll() {
    for (const kind of ["dns", "tls"]) {
      const btn = $(kind + "-btn");
      btn.disabled = Boolean(checking);
      btn.textContent = t(checking === kind ? "checking" : btn.getAttribute("data-i18n"));
      const result = state[kind];
      if (checking === kind) setText(kind + "-result", t("checking"));
      else if (result) setText(kind + "-result", t(result.key), result.cls);
    }
    renderVerdict();
  }

  function renderVerdict() {
    const box = $("verdict");
    if (checking || (!state.dns && !state.tls)) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");
    setText("verdict-dns", state.dns ? t("dnsPrefix") + t(state.dns.key) : "");
    setText("verdict-tls", state.tls ? t("tlsPrefix") + t(state.tls.key) : "");
    if (!state.dns || !state.tls) {
      setText("verdict-summary", t("verdictNotRun"), "warn");
      return;
    }

    const dns = state.dns.key;
    const tls = state.tls.key;
    const key = {
      "dnsSafe:tlsGood": "verdictClean",
      "dnsSafe:tlsBad": "verdictTlsOnly",
      "dnsSafe:tlsUnknown": "verdictDnsSafeTlsUnknown",
      "dnsBad:tlsGood": "verdictBadButValid",
      "dnsBad:tlsBad": "verdictDanger",
      "dnsBad:tlsUnknown": "verdictStopped",
      "dnsUnknown:tlsGood": "verdictUnknownDnsValid",
      "dnsUnknown:tlsBad": "verdictTlsOnlyDnsUnknown",
      "dnsUnknown:tlsUnknown": "verdictUnknown"
    }[dns + ":" + tls] || "verdictUnknown";
    setText("verdict-summary", t(key), tls === "tlsBad" ? "bad" : "warn");
  }

  async function fetchJson(url, ms = 10000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      const res = await fetch(url, { cache: "no-store", signal: ctrl.signal, credentials: "omit", redirect: "error" });
      let data = null;
      try { data = await res.json(); } catch (_) {}
      return { ok: res.ok, data };
    } finally {
      clearTimeout(timer);
    }
  }

  async function checkDns() {
    if (checking) return;
    checking = "dns";
    renderAll();
    try {
      const label = "r" + crypto.randomUUID().replace(/-/g, "");
      const host = label + "." + cfg.labDomain;
      const url = "https://" + host + "/probe?token=" + encodeURIComponent(label);
      const res = await fetchJson(url);
      if (!res.ok || !res.data || res.data.token !== label || res.data.host !== host) {
        throw new Error("Invalid DNS probe response");
      }
      if (res.data.path === "fake") {
        state.dns = { key: "dnsBad", cls: "bad" };
      } else if (res.data.path === "true") {
        state.dns = { key: "dnsSafe", cls: "good" };
      } else {
        state.dns = { key: "dnsUnknown", cls: "warn" };
      }
    } catch (_) {
      state.dns = { key: "dnsUnknown", cls: "warn" };
    } finally {
      checking = null;
      renderAll();
    }
  }

  async function checkTls() {
    if (checking) return;
    checking = "tls";
    renderAll();
    try {
      const res = await fetchJson("https://" + cfg.mitmHost + "/tls-probe");
      if (!res.ok || !res.data || res.data.host !== cfg.mitmHost || !isSha256(res.data.leaf_sha256)) {
        throw new Error("Invalid TLS probe response");
      }
      if (res.data.tls === "forged" && isSha256(res.data.issuer_spki_sha256)) {
        state.tls = { key: "tlsBad", cls: "bad" };
      } else if (res.data.tls === "other") {
        state.tls = { key: "tlsGood", cls: "warn" };
      } else {
        state.tls = { key: "tlsUnknown", cls: "warn" };
      }
    } catch (_) {
      // fetch() does not expose certificate errors. A failure can mean the
      // certificate was rejected, the network failed, or the lab is down.
      state.tls = { key: "tlsUnknown", cls: "warn" };
    } finally {
      checking = null;
      renderAll();
    }
  }

  function wire() {
    window.YIP_I18N.apply();
    $("lang-ja").addEventListener("click", () => {
      window.YIP_I18N.setLang("ja");
      renderAll();
    });
    $("lang-en").addEventListener("click", () => {
      window.YIP_I18N.setLang("en");
      renderAll();
    });
    $("dns-btn").addEventListener("click", checkDns);
    $("tls-btn").addEventListener("click", checkTls);

    document.querySelectorAll("[data-releases]").forEach((a) => {
      a.href = cfg.releasesUrl || "#";
      a.target = "_blank";
      a.rel = "noopener";
    });
  }

  window.addEventListener("DOMContentLoaded", wire);
})();
