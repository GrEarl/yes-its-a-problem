"use strict";
(function () {
  const dict = {
    ja: {
      ribbon: "PoC",
      pocNotice: "空手形銀行は架空の銀行です。実際の振込は行われません。",
      bankName: "空手形銀行",
      paymentTitle: "振込内容",
      payee: "送金先",
      account: "口座",
      amount: "金額",
      amountUsd: "(約 10 USD)",
      quoteBtn: "内容を確認",
      payBtn: "送金する",
      receivedTitle: "受信した内容",
      dangerDns: "危険: DNS が汚染され、偽装された通信経路を経由しています。",
      safeBody: "安全: 証明書の検証に失敗したため、接続は確立されませんでした。",
      electronUnavailable: "Electron で起動してください。",
      loading: "取得中...",
      quoteFailed: "判定不能: 振込内容を取得できませんでした。",
      requestFailed: "判定不能: 通信に失敗しました。",
      quoteOk: "振込内容を受信しました。",
      tampered: "送金先、口座、金額のいずれかが一致しません。",
      paid: "デモ送金を完了しました。",
      receipt: "デモ領収書"
    },
    en: {
      ribbon: "PoC",
      pocNotice: "Karategata Banking is fictional. No real transfer is made.",
      bankName: "Karategata Banking Corporation",
      paymentTitle: "Transfer details",
      payee: "Payee",
      account: "Account",
      amount: "Amount",
      amountUsd: "(about USD 10)",
      quoteBtn: "Review",
      payBtn: "Send",
      receivedTitle: "Received",
      dangerDns: "DANGER: Your DNS is poisoned, and traffic is routed through a forged network path.",
      safeBody: "SAFE: Certificate verification failed, so the connection was not established.",
      electronUnavailable: "Start this app with Electron.",
      loading: "Fetching...",
      quoteFailed: "INCONCLUSIVE: Could not fetch the transfer details.",
      requestFailed: "INCONCLUSIVE: The request failed.",
      quoteOk: "Transfer details received.",
      tampered: "The payee, account, or amount does not match.",
      paid: "Demo payment completed.",
      receipt: "Demo receipt"
    }
  };

  let lang = "en";
  try {
    const saved = localStorage.getItem("kbc-lang");
    if (saved === "ja" || saved === "en") lang = saved;
    else {
      const first = String((navigator.languages && navigator.languages[0]) || navigator.language || "").toLowerCase();
      if (first.startsWith("ja")) lang = "ja";
    }
  } catch (_) {}

  function t(key) {
    return (dict[lang] && dict[lang][key]) || dict.en[key] || key;
  }
  function apply(root) {
    const scope = root || document;
    scope.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    document.documentElement.lang = lang;
    document.querySelectorAll(".lang-btn").forEach((b) => {
      b.classList.toggle("active", b.id === "lang-" + lang);
    });
  }
  function setLang(next) {
    if (next !== "ja" && next !== "en") return;
    lang = next;
    try { localStorage.setItem("kbc-lang", lang); } catch (_) {}
    apply();
    window.dispatchEvent(new CustomEvent("kbc-lang", { detail: lang }));
  }
  window.KBC_I18N = { t, apply, setLang, getLang: () => lang };
})();
