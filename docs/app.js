"use strict";
(function () {
  const cfg = window.YIP_CONFIG || {};
  const t = (k) => (window.YIP_I18N ? window.YIP_I18N.t(k) : k);
  const $ = (id) => document.getElementById(id);
  const state = { dns: null, tls: null };
  let checking = false;

  function setText(id, text, cls) {
    const el = $(id);
    el.textContent = text || "";
    el.className = "result" + (cls ? " " + cls : "");
  }

  function setBusy(btn, busyKey) {
    if (!btn) return;
    if (checking) return;
    btn.disabled = true;
    btn.dataset.original = btn.textContent;
    btn.textContent = t(busyKey);
  }
  function clearBusy(btn) {
    if (!btn) return;
    btn.disabled = false;
    if (btn.dataset.original) btn.textContent = btn.dataset.original;
  }

  function renderAll() {
    if (state.dns) setText("dns-result", t(state.dns.key), state.dns.cls);
    if (state.tls) setText("tls-result", t(state.tls.key), state.tls.cls);
    renderVerdict();
  }

  function renderVerdict() {
    const box = $("verdict");
    const txt = $("verdict-text");
    if (!state.dns && !state.tls) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");
    const dnsBad = state.dns && state.dns.key === "dnsBad";
    const tlsBad = state.tls && state.tls.key === "tlsBad";
    const dnsUnknown = !state.dns || state.dns.key === "dnsUnknown";
    const tlsUnknown = !state.tls || state.tls.key === "tlsUnknown";
    if (dnsUnknown && tlsUnknown) {
      txt.textContent = t("verdictUnknown");
      txt.className = "warn";
    } else if (dnsBad && tlsBad) {
      txt.textContent = t("verdictDanger");
      txt.className = "bad";
    } else {
      txt.textContent = t("verdictMixed");
      txt.className = "warn";
    }
  }

  async function fetchJson(url, ms = 10000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      const res = await fetch(url, { cache: "no-store", signal: ctrl.signal, credentials: "omit" });
      let data = null;
      try { data = await res.json(); } catch (_) {}
      return { ok: res.ok, status: res.status, data };
    } finally {
      clearTimeout(timer);
    }
  }

  async function checkDns() {
    if (checking) return;
    checking = true;
    const btn = $("dns-btn");
    setBusy(btn, "dnsButtonBusy");
    setText("dns-result", t("checking"), "");
    try {
      const label = "r" + Math.random().toString(16).slice(2, 10);
      const url = "https://" + label + "." + cfg.labDomain + "/probe?token=" + encodeURIComponent(label);
      const res = await fetchJson(url);
      if (res.ok && res.data && res.data.path === "fake") {
        state.dns = { key: "dnsBad", cls: "bad" };
      } else if (res.ok && res.data && res.data.path === "true") {
        state.dns = { key: "dnsSafe", cls: "good" };
      } else {
        state.dns = { key: "dnsUnknown", cls: "warn" };
      }
    } catch (_) {
      state.dns = { key: "dnsUnknown", cls: "warn" };
    } finally {
      checking = false;
      clearBusy(btn);
      renderAll();
    }
  }

  async function checkTls() {
    if (checking) return;
    checking = true;
    const btn = $("tls-btn");
    setBusy(btn, "tlsButtonBusy");
    setText("tls-result", t("checking"), "");
    try {
      const res = await fetchJson("https://" + cfg.mitmHost + "/tls-probe");
      if (res.ok && res.data && res.data.tls === "forged") {
        state.tls = { key: "tlsBad", cls: "bad" };
      } else {
        state.tls = { key: "tlsUnknown", cls: "warn" };
      }
    } catch (_) {
      // The browser does not expose certificate errors to fetch().  A failure
      // here can mean "protected" or "lab unreachable"; we do not claim either.
      state.tls = { key: "tlsUnknown", cls: "warn" };
    } finally {
      checking = false;
      clearBusy(btn);
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
