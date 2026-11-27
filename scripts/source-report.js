/**
 * Fork: "Where did this link come from?" form on the block page.
 *
 * The user says where the link came from (email sender + subject, Teams, shared file, text, website)
 * and whether they typed their password. The answer goes out as a `user_report` webhook, so the
 * MSP can find and purge the email for everyone who received it, and reset the password if needed.
 *
 * Shown only when the managed genericWebhook lists the `user_report` event.
 * Kept in its own file so upstream changes to blocked.js merge cleanly.
 */
(function () {
  "use strict";

  const SOURCE_LABELS = {
    email: "An email",
    teams: "Teams or another chat",
    sharedfile: "A shared file or SharePoint/OneDrive page",
    sms: "A text message",
    web: "Another website or search result",
    unknown: "I'm not sure",
  };
  const EMAIL_RE = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]{2,}$/;

  const $ = (id) => document.getElementById(id);
  const clip = (s, n) => String(s || "").trim().slice(0, n);

  // A pasted web address, with or without https://. Returns the cleaned address, or "" if it isn't one.
  function parseSite(raw) {
    const text = String(raw || "").trim().slice(0, 2048);
    if (!text) return "";
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : "https://" + text);
      if (!/^https?:$/.test(u.protocol) || !/\.[a-z]{2,}$/i.test(u.hostname)) return "";
      return u.href;
    } catch (e) {
      return "";
    }
  }
  let company = "IT"; // replaced by customBranding.companyName when set

  // Accept "Name <someone@example.com>" as pasted from Outlook, or a bare address.
  function parseSender(raw) {
    const text = clip(raw, 320);
    if (!text) return { raw: "", address: "" };
    const m = text.match(/<([^<>\s]+@[^<>\s]+)>/) || text.match(/([^\s<>"]+@[^\s<>"]+\.[^\s<>"]{2,})/);
    const address = m ? m[1].toLowerCase() : "";
    return { raw: text, address: EMAIL_RE.test(address) ? address : "" };
  }

  function selected(name) {
    const el = document.querySelector(`input[name="${name}"]:checked`);
    return el ? el.value : "";
  }

  function setStatus(kind, text) {
    const s = $("srcStatus");
    s.className = "src-status " + kind;
    s.textContent = text;
    s.hidden = !text;
  }

  function toggleFields() {
    const type = selected("srcType");
    $("srcEmailFields").hidden = type !== "email";
    $("srcSharedFields").hidden = type !== "sharedfile";
    $("srcWebFields").hidden = type !== "web";
    $("srcSubmitBtn").disabled = !type;
    updatePasswordHint();
  }

  function updatePasswordHint() {
    const pw = selected("srcPassword");
    $("srcUrgent").hidden = pw !== "yes" && pw !== "unsure";
  }

  function getBranding() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: "GET_BRANDING_CONFIG" }, (r) => {
          if (chrome.runtime.lastError || !r || !r.success) return resolve(null);
          resolve(r.branding || null);
        });
      } catch (e) {
        resolve(null);
      }
    });
  }

  function details() {
    // blocked.js keeps the parsed block details in a top-level `let`, which is visible here.
    try {
      // eslint-disable-next-line no-undef
      return globalDetectionDetails || {};
    } catch (e) {
      return {};
    }
  }

  function buildReport() {
    const type = selected("srcType");
    const d = details();
    const sender = parseSender($("srcSender").value);
    return {
      url: d.url || "",
      blockedReason: clip($("blockReason").textContent.replace(/\s+/g, " "), 500),
      rule: d.rule || d.ruleDescription || "",
      referrer: d.referrer || "",
      source: {
        type: type,
        label: SOURCE_LABELS[type] || type,
        sender: sender.raw,
        senderAddress: sender.address,
        subject: type === "email" ? clip($("srcSubject").value, 300) : "",
        receivedAround: type === "email" ? clip($("srcWhen").value, 60) : "",
        sharedBy: type === "sharedfile" ? clip($("srcSharedBy").value, 200) : "",
        site: type === "web" ? parseSite($("srcSite").value) : "",
        note: clip($("srcNote").value, 1000),
      },
      enteredPassword: selected("srcPassword") || "unknown",
      timestamp: new Date().toISOString(),
    };
  }

  async function submit(ev) {
    ev.preventDefault();
    const report = buildReport();
    if (!report.source.type) return setStatus("warn", "Pick where the link came from.");
    if (report.source.type === "email" && !report.source.sender && !report.source.subject) {
      return setStatus("warn", "Add the sender's address or the subject, so we can find the email.");
    }
    if (report.source.type === "web" && clip($("srcSite").value, 2048) && !report.source.site) {
      return setStatus("warn", "That doesn't look like a web address. Copy it from the address bar.");
    }
    if (report.source.type === "email" && report.source.sender && !report.source.senderAddress) {
      return setStatus("warn", "That sender doesn't look like an email address. Copy it from the 'From' line in Outlook.");
    }
    const btn = $("srcSubmitBtn");
    btn.disabled = true;
    btn.textContent = "Sending…";
    setStatus("", "");
    try {
      const r = await chrome.runtime.sendMessage({ type: "send_webhook", webhookType: "user_report", data: report });
      if (!r || !r.success) throw new Error((r && r.error) || "not sent");
      $("srcForm").hidden = true;
      setStatus(
        "ok",
        report.enteredPassword === "yes" || report.enteredPassword === "unsure"
          ? `Thank you, ${company} has your report. Because you may have typed your password, call ${company} now.`
          : `Thank you, ${company} has your report. They'll remove it from everyone else's mailbox. You can close this tab.`
      );
    } catch (e) {
      btn.disabled = false;
      btn.textContent = `Send to ${company}`;
      setStatus("bad", `That didn't send. Contact ${company} instead.`);
    }
  }

  async function init() {
    const section = $("sourceReport");
    if (!section) return;
    // blocked.html is web-accessible, so any site can frame it; never show the form inside a frame,
    // where a page could overlay it and trick the user into sending a report (clickjacking).
    if (window.top !== window) return;
    const b = await getBranding();
    const wh = b && b.genericWebhook;
    const on = !!(wh && wh.enabled && wh.url && Array.isArray(wh.events) && wh.events.includes("user_report"));
    if (!on) return; // stock behaviour when not configured

    const phone = clip(b.supportPhone, 40);
    if (phone) {
      const tel = phone.replace(/[^\d+]/g, "");
      ["srcPhoneLink", "srcUrgentPhone"].forEach((id) => {
        const a = $(id);
        if (a) { a.textContent = phone; a.href = "tel:" + tel; }
      });
      $("srcPhoneLine").hidden = false;
    } else {
      $("srcUrgentPhoneWrap").hidden = true;
    }
    company = clip(b.companyName, 60) || "IT";
    $("srcCompany").textContent = company;
    $("srcSubmitBtn").textContent = `Send to ${company}`;

    document.querySelectorAll('input[name="srcType"]').forEach((el) => el.addEventListener("change", toggleFields));
    document.querySelectorAll('input[name="srcPassword"]').forEach((el) => el.addEventListener("change", updatePasswordHint));
    $("srcForm").addEventListener("submit", submit);
    toggleFields();
    section.hidden = false;
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
