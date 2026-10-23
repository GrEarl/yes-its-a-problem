"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const t = (k) => (window.KBC_I18N ? window.KBC_I18N.t(k) : k);

  let cfg = null;
  let quote = null;

  function money(amount) {
    try {
      return new Intl.NumberFormat(window.KBC_I18N && window.KBC_I18N.getLang() === "ja" ? "ja-JP" : "en-US", {
        style: "currency", currency: "JPY", maximumFractionDigits: 0
      }).format(Number(amount) || 0);
    } catch (_) {
      return "¥" + String(amount);
    }
  }

  function setStatus(text, cls) {
    const el = $("status");
    el.textContent = text || "";
    el.className = "status" + (cls ? " " + cls : "");
  }

  function show(el, yes) {
    el.classList.toggle("hidden", !yes);
  }

  function clearNotices() {
    show($("danger"), false);
    show($("safe"), false);
  }

  function isCertError(message) {
    return /ERR_CERT_[A-Z_]+/.test(String(message || ""));
  }

  function hideReceived() {
    show($("received"), false);
  }

  function isQuote(data) {
    return !!data && typeof data === "object" &&
      typeof data.merchant === "string" &&
      typeof data.account === "string" &&
      Number.isFinite(Number(data.amount));
  }

  function handleNetFailure(message, failKey) {
    if (isCertError(message)) {
      showSafe();
      setStatus("", "ok");
    } else {
      clearNotices();
      hideReceived();
      setStatus(t(failKey), "warn");
    }
  }

  function renderExpected() {
    if (!cfg) return;
    $("expected-payee").textContent = cfg.expected.merchant;
    $("expected-account").textContent = cfg.expected.account;
    $("expected-amount").textContent = money(cfg.expected.amount);
  }

  function renderQuote(data) {
    $("recv-payee").textContent = data.merchant || "-";
    $("recv-account").textContent = data.account || "-";
    $("recv-amount").textContent = money(data.amount);
    show($("received"), true);
  }

  function isTampered(data) {
    if (!cfg || !data) return true;
    return String(data.merchant) !== String(cfg.expected.merchant) ||
           String(data.account) !== String(cfg.expected.account) ||
           Number(data.amount) !== Number(cfg.expected.amount);
  }

  function showDanger() {
    show($("danger"), true);
    show($("safe"), false);
  }

  function showSafe() {
    show($("danger"), false);
    show($("safe"), true);
    hideReceived();
  }

  async function getQuote() {
    if (!window.kbc) {
      setStatus(t("electronUnavailable"), "bad");
      return;
    }
    $("quote-btn").disabled = true;
    $("pay-btn").disabled = true;
    setStatus(t("loading"), "");
    try {
      const res = await window.kbc.quote();
      if (!res.ok) {
        console.error("quote failed:", res.error || ("HTTP " + res.status));
        handleNetFailure(res.error, "quoteFailed");
        return;
      }
      if (!res.jsonValid || !isQuote(res.data)) {
        clearNotices();
        hideReceived();
        setStatus(t("quoteFailed"), "warn");
        return;
      }
      quote = res.data;
      renderQuote(quote);
      if (isTampered(quote)) {
        showDanger();
        setStatus(t("tampered"), "bad");
      } else {
        clearNotices();
        setStatus(t("quoteOk"), "ok");
      }
      $("pay-btn").disabled = false;
    } catch (e) {
      const message = String(e && e.message ? e.message : e);
      console.error("request failed:", message);
      handleNetFailure(message, "quoteFailed");
    } finally {
      $("quote-btn").disabled = false;
    }
  }

  async function pay() {
    if (!window.kbc || !quote) return;
    $("pay-btn").disabled = true;
    setStatus(t("loading"), "");
    try {
      const res = await window.kbc.pay();
      if (!res.ok) {
        console.error("payment failed:", res.error || ("HTTP " + res.status));
        handleNetFailure(res.error, "requestFailed");
        return;
      }
      if (!res.jsonValid) {
        clearNotices();
        hideReceived();
        setStatus(t("requestFailed"), "warn");
        return;
      }
      const data = res.data || {};
      if (data.account || data.amount || data.merchant) renderQuote(data);
      if (isTampered(data)) {
        showDanger();
        setStatus(t("paidWith").replace("%s", data.receipt || "-"), "bad");
      } else {
        clearNotices();
        setStatus(t("paidWith").replace("%s", data.receipt || "-"), "ok");
      }
    } catch (e) {
      const message = String(e && e.message ? e.message : e);
      console.error("request failed:", message);
      handleNetFailure(message, "requestFailed");
    } finally {
      $("pay-btn").disabled = false;
    }
  }

  async function init() {
    window.KBC_I18N.apply();
    $("lang-ja").addEventListener("click", () => {
      window.KBC_I18N.setLang("ja");
      renderExpected();
      if (quote) renderQuote(quote);
    });
    $("lang-en").addEventListener("click", () => {
      window.KBC_I18N.setLang("en");
      renderExpected();
      if (quote) renderQuote(quote);
    });
    $("quote-btn").addEventListener("click", getQuote);
    $("pay-btn").addEventListener("click", pay);

    if (!window.kbc) {
      setStatus(t("electronUnavailable"), "bad");
      return;
    }
    cfg = await window.kbc.config();
    renderExpected();
  }

  window.addEventListener("DOMContentLoaded", init);
})();
