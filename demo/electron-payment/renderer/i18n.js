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
      dangerMismatch: "危険: 送金先、口座、金額のいずれかが振込内容と一致しません。",
      safeBody: "安全: 証明書の検証に失敗したため、接続は確立されませんでした。",
      electronUnavailable: "Electron で起動してください。",
      loading: "取得中...",
      quoteFailed: "判定不能: 振込内容を取得できませんでした。",
      requestFailed: "判定不能: 通信または応答に問題がありました。",
      quoteOk: "振込内容を受信しました。",
      tampered: "送金先、口座、金額のいずれかが一致しません。",
      paidWith: "PoC の送金を完了しました。（PoC 領収書 %s）"
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
      dangerMismatch: "DANGER: The payee, account, or amount does not match the expected values.",
      safeBody: "SAFE: Certificate verification failed, so the connection was not established.",
      electronUnavailable: "Start this app with Electron.",
      loading: "Fetching...",
      quoteFailed: "INCONCLUSIVE: Could not fetch the transfer details.",
      requestFailed: "INCONCLUSIVE: There was a problem with the request or the response.",
      quoteOk: "Transfer details received.",
      tampered: "The payee, account, or amount does not match.",
      paidWith: "PoC payment completed. (PoC receipt %s)"
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
  function apply() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
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
  }
  window.KBC_I18N = { t, apply, setLang, getLang: () => lang };
})();
