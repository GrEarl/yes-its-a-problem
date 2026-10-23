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
    if (!state.dns && !state.tls) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");
    setText("verdict-dns", state.dns ? t("dnsPrefix") + t(state.dns.key) : "");
    setText("verdict-tls", state.tls ? t("tlsPrefix") + t(state.tls.key) : "");
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

  async function controlReachable() {
    if (!cfg.controlUrl) return false;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
      await fetch(cfg.controlUrl, {
        mode: "no-cors",
        cache: "no-store",
        credentials: "omit",
        signal: ctrl.signal
      });
      return true;
    } catch (_) {
      return false;
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
      } else if (res.ok && res.data && res.data.tls === "valid") {
        state.tls = { key: "tlsValid", cls: "good" };
      } else {
        state.tls = { key: "tlsUnknown", cls: "warn" };
      }
    } catch (_) {
      // fetch() does not expose the certificate error itself.  If the
      // control host is reachable, the failure is consistent with rejection,
      // not proof of it.
      const reachable = await controlReachable();
      state.tls = reachable
        ? { key: "tlsRejected", cls: "warn" }
        : { key: "tlsUnknown", cls: "warn" };
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
