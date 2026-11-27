/**
 * Fork: warning banner UI (replaces the look of upstream's showWarningBanner).
 *
 * Plain-language titles, solid high-contrast colours, no emoji, and a report-first flow:
 *   1. "Report it to <company>" opens a short form inside the banner
 *      (where the link came from, sender/subject, "did you type your password?").
 *   2. The answer is sent as a `user_report` webhook (same payload as the block-page form).
 *   3. Only then does "Leave this page" become the main action.
 *
 * Rendered in a closed shadow root: the page's CSS can't restyle it, the page's scripts can't read what
 * the user types, and its inputs don't feed the page's own phishing heuristics.
 * Content scripts share one isolated world, so content.js calls GuardianBanner.render(...).
 */
// eslint-disable-next-line no-unused-vars
var GuardianBanner = (function () {
  "use strict";

  const shadows = new WeakMap();
  const state = new WeakMap(); // per banner: { step, report }
  const EMAIL_RE = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]{2,}$/;

  const THEMES = {
    danger: { bg: "#A32D2D", fg: "#FFFFFF", sub: "#FCEBEB", line: "#E24B4A", btnBg: "#FFFFFF", btnFg: "#791F1F", chipOnFg: "#791F1F" },
    caution: { bg: "#FAEEDA", fg: "#412402", sub: "#633806", line: "#EF9F27", btnBg: "#633806", btnFg: "#FAEEDA", chipOnFg: "#FAEEDA", chipOnBg: "#633806" },
    info: { bg: "#E6F1FB", fg: "#042C53", sub: "#0C447C", line: "#85B7EB", btnBg: "#0C447C", btnFg: "#E6F1FB" },
  };

  const SOURCES = [
    ["email", "An email"],
    ["sharedfile", "A shared file"],
    ["teams", "Teams or chat"],
    ["sms", "A text message"],
    ["web", "A website"],
    ["unknown", "Not sure"],
  ];

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

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
      else if (k === "text") e.textContent = v;
      else e.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k) e.append(k);
    return e;
  }

  // Shield outline icon (inline SVG; no emoji, no external fonts).
  function shield(size) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", size);
    svg.setAttribute("height", size);
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    for (const d of ["M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6z", "M9 12l2 2 4-4"]) {
      const p = document.createElementNS(ns, "path");
      p.setAttribute("d", d);
      svg.append(p);
    }
    return svg;
  }

  function css(t, compact) {
    return `
      :host { all: initial; }
      * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
      .bar { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 16px; align-items: start;
             background: ${t.bg}; color: ${t.fg}; padding: ${compact ? "8px 16px" : "14px 18px"};
             border-bottom: 1px solid ${t.line}; box-shadow: 0 2px 8px rgba(0,0,0,.25); text-align: left; }
      .brand { display: flex; gap: 8px; align-items: center; font-size: 12px; line-height: 1.25; color: ${t.fg}; padding-top: 2px; }
      .brand b { font-weight: 600; }
      .title { font-size: ${compact ? "14px" : "17px"}; font-weight: 600; margin: 0; color: ${t.fg}; line-height: 1.3; }
      .msg { font-size: 14px; line-height: 1.5; margin: 3px 0 0; color: ${t.sub}; }
      .urgent { font-size: 14px; font-weight: 600; margin: 8px 0 0; color: ${t.fg}; }
      .acts { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 12px; }
      button { font: inherit; font-size: 14px; cursor: pointer; border-radius: 6px; padding: 7px 14px;
               border: 1px solid ${t.fg}; background: transparent; color: ${t.fg}; line-height: 1.2; }
      button.primary { background: ${t.btnBg}; color: ${t.btnFg}; border-color: ${t.btnBg}; font-weight: 600; }
      button:focus-visible, a:focus-visible, input:focus-visible { outline: 2px solid ${t.fg}; outline-offset: 2px; }
      a { color: ${t.fg}; }
      .link { background: none; border: 0; padding: 0; font-size: 13px; text-decoration: underline; color: ${t.fg}; }
      .why { font-size: 13px; line-height: 1.5; margin-top: 12px; padding-top: 8px; border-top: 1px solid ${t.line}; color: ${t.sub}; }
      .why b { color: ${t.fg}; font-weight: 600; }
      .x { border: 0; background: transparent; font-size: 22px; line-height: 1; padding: 0 4px; color: ${t.fg}; }
      .form { margin-top: 10px; padding: 12px; border: 1px solid ${t.line}; border-radius: 8px; display: grid; gap: 10px; }
      .q { font-size: 13px; font-weight: 600; color: ${t.fg}; margin: 0 0 6px; }
      .chips { display: flex; flex-wrap: wrap; gap: 6px; }
      .chip { font-size: 13px; padding: 5px 11px; border-radius: 999px; border: 1px solid ${t.line}; font-weight: 400; }
      .chip[aria-pressed="true"] { background: ${t.chipOnBg || t.btnBg}; color: ${t.chipOnFg}; border-color: ${t.chipOnBg || t.btnBg}; font-weight: 600; }
      label { display: grid; gap: 4px; font-size: 13px; font-weight: 600; color: ${t.fg}; }
      input { font: inherit; font-size: 14px; font-weight: 400; padding: 7px 9px; border-radius: 6px;
              border: 1px solid ${t.line}; background: #FFFFFF; color: #1F1F1F; width: 100%; max-width: 480px; }
      .hint { font-size: 12px; font-weight: 400; color: ${t.sub}; }
      .err { font-size: 13px; font-weight: 600; color: ${t.fg}; background: rgba(0,0,0,.18); padding: 6px 9px; border-radius: 6px; }
      [hidden] { display: none !important; }
    `;
  }

  function getShadow(host) {
    let sr = shadows.get(host);
    if (!sr) {
      sr = host.attachShadow({ mode: "closed" });
      shadows.set(host, sr);
    }
    return sr;
  }

  function texts(kind, opts) {
    const company = opts.company;
    const reporting = opts.canReport;
    const dont = "Don't type your password or any codes here.";
    const tell = reporting ? ` Tell ${company} where you found this link, so they can remove it for everyone.` : "";
    switch (kind) {
      case "scanning":
        return { title: "Checking this sign-in page before you type anything…", msg: "" };
      case "rogue":
        return { title: "Stop: this app is trying to get into your Microsoft 365 account",
                 msg: "Don't approve it or accept any permissions." + tell };
      case "squatting":
        return { title: opts.protectedDomain ? `Be careful: this address imitates ${opts.protectedDomain}` : "Be careful: this web address imitates a trusted site",
                 msg: "It isn't one of your organisation's sites. Don't sign in or download anything unless " + company + " confirms it's genuine." };
      case "critical":
        return { title: "Stop: this isn't a real Microsoft sign-in page", msg: dont + " It's designed to steal your Microsoft 365 account." + tell };
      default: // high / warning
        return { title: "Be careful: this may not be a real Microsoft sign-in page", msg: dont + tell };
    }
  }

  // Upstream reasons are technical; say the common ones in plain words.
  function friendlyReason(reason) {
    const r = String(reason || "");
    const m = r.match(/Form action\s+"?(https?:\/\/[^"\s]+)"?/i);
    if (m) {
      let host = m[1];
      try { host = new URL(m[1]).hostname; } catch (_) {}
      return `the sign-in form sends your details to ${host} instead of Microsoft.`;
    }
    if (/domain squatting|typosquat/i.test(r)) return "the web address is a close copy of a trusted one.";
    if (/rogue/i.test(r)) return "this app is on a list of apps known to be used in attacks.";
    return clip(r.replace(/^(CRITICAL THREATS DETECTED|THREAT DETECTED):\s*/i, ""), 220);
  }

  function leavePage() {
    try {
      if (history.length > 1) { history.back(); return; }
    } catch (_) {}
    location.replace("about:blank");
  }

  /**
   * opts: { kind, reason, protectedDomain, branding, onDismiss(), onLayout(), onFalsePositive(), details }
   * kind: scanning | critical | rogue | high | squatting | warning
   */
  function render(host, opts, internal) {
    const st = state.get(host) || { step: "initial", report: null };
    state.set(host, st);
    // A re-scan or late branding must not wipe a form the user is filling in or a thank-you they haven't read.
    if (!internal && st.step !== "initial") return;
    st.kind = opts.kind;

    const b = opts.branding || {};
    const wh = b.genericWebhook;
    const company = clip(b.companyName, 60) || clip(b.productName, 60) || "IT";
    const phone = clip(b.supportPhone, 40);
    const canReport = !!(wh && wh.enabled && wh.url && Array.isArray(wh.events) && wh.events.includes("user_report"));
    const kind = opts.kind;
    const compact = kind === "scanning";
    const theme = compact ? THEMES.info : (kind === "critical" || kind === "rogue") ? THEMES.danger : THEMES.caution;
    const t = texts(kind, { company, canReport, protectedDomain: opts.protectedDomain });

    const sr = getShadow(host);
    const layout = () => { try { opts.onLayout && opts.onLayout(); } catch (_) {} };

    const brand = el("div", { class: "brand" }, shield(compact ? 18 : 24),
      compact ? el("span", { text: company === "IT" ? "" : company })
              : el("span", {}, "Protected by", el("br"), el("b", { text: company === "IT" ? "your IT team" : company })));

    const close = el("button", { class: "x", type: "button", "aria-label": "Dismiss warning", title: "Dismiss",
      on: { click: () => opts.onDismiss && opts.onDismiss() } }, "×");

    const callBtn = phone
      ? el("button", { type: "button", on: { click: () => { location.href = "tel:" + phone.replace(/[^\d+]/g, ""); } } }, "Call " + phone)
      : null;

    let body;
    if (compact) {
      body = el("p", { class: "title" }, t.title);
    } else if (st.step === "thanks") {
      const pw = st.report && (st.report.enteredPassword === "yes" || st.report.enteredPassword === "unsure");
      const fromEmail = st.report && st.report.source && st.report.source.type === "email";
      body = el("div", {},
        el("p", { class: "title" }, `Thanks, ${company} has your report`),
        el("p", { class: "msg" }, (fromEmail ? "They'll remove this email from everyone else's mailbox. " : "") + "Now close this page."),
        pw ? el("p", { class: "urgent" }, phone ? `You may have typed your password: call ${company} now on ${phone} so they can secure your account.`
                                                 : `You may have typed your password: contact ${company} now so they can secure your account.`) : null,
        el("div", { class: "acts" },
          el("button", { class: "primary", type: "button", on: { click: leavePage } }, "Leave this page"),
          pw ? callBtn : null));
    } else if (st.step === "form") {
      body = buildForm();
    } else {
      const why = el("div", { class: "why" }, el("b", {}, "Why we flagged it: "), friendlyReason(opts.reason), " ",
        opts.onFalsePositive ? el("button", { class: "link", type: "button", on: { click: (e) => opts.onFalsePositive(e) } }, "Think this is wrong?") : null);
      const acts = canReport
        ? [el("button", { class: "primary", type: "button", on: { click: () => { st.step = "form"; render(host, opts, true); } } }, `Report it to ${company}`),
           callBtn,
           el("button", { class: "link", type: "button", on: { click: leavePage } }, "Leave without reporting")]
        : [el("button", { class: "primary", type: "button", on: { click: leavePage } }, "Leave this page"), callBtn];
      body = el("div", {}, el("p", { class: "title" }, t.title), el("p", { class: "msg" }, t.msg), el("div", { class: "acts" }, acts), why);
    }

    function buildForm() {
      const sel = { src: "", pw: "" };
      const err = el("div", { class: "err", role: "alert", hidden: true });
      const sender = el("input", { type: "text", maxlength: "320", autocomplete: "off", placeholder: "name@company.com", "aria-label": "Who was it from?" });
      const subject = el("input", { type: "text", maxlength: "300", autocomplete: "off", placeholder: "Invoice 4471 shared with you", "aria-label": "Subject line" });
      const sharedBy = el("input", { type: "text", maxlength: "200", autocomplete: "off", placeholder: "Jane at Contoso Supply", "aria-label": "Who shared it" });
      const emailBox = el("div", { hidden: true, style: "display:grid;gap:8px" },
        el("label", {}, "Who was it from?", sender, el("span", { class: "hint", text: "Copy the address from the email's From line." })),
        el("label", {}, "Subject line", subject));
      const sharedBox = el("div", { hidden: true }, el("label", {}, "Who shared it with you, or which company?", sharedBy));
      const site = el("input", { type: "text", maxlength: "2048", autocomplete: "off", placeholder: "https://example.com/page", "aria-label": "Which website?" });
      const siteBox = el("div", { hidden: true }, el("label", {}, "Which website?", site,
        el("span", { class: "hint", text: "Copy the address from the tab where you clicked the link, if you still have it." })));
      const chipRow = (items, key, onPick) => {
        const row = el("div", { class: "chips", role: "group" });
        for (const [val, label] of items) {
          row.append(el("button", { class: "chip", type: "button", "aria-pressed": "false", "data-v": val,
            on: { click: () => {
              sel[key] = val;
              row.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.v === val)));
              onPick && onPick(val);
              err.hidden = true;
              layout();
            } } }, label));
        }
        return row;
      };
      const srcRow = chipRow(SOURCES, "src", (v) => { emailBox.hidden = v !== "email"; sharedBox.hidden = v !== "sharedfile"; siteBox.hidden = v !== "web"; });
      const pwRow = chipRow([["no", "No"], ["yes", "Yes"], ["unsure", "Not sure"]], "pw");
      const sendBtn = el("button", { class: "primary", type: "button" }, `Send to ${company}`);

      sendBtn.addEventListener("click", async () => {
        const fail = (m) => { err.textContent = m; err.hidden = false; layout(); };
        if (!sel.src) return fail("Pick where the link came from.");
        const raw = clip(sender.value, 320);
        const m = raw.match(/<([^<>\s]+@[^<>\s]+)>/) || raw.match(/([^\s<>"]+@[^\s<>"]+\.[^\s<>"]{2,})/);
        const addr = m && EMAIL_RE.test(m[1]) ? m[1].toLowerCase() : "";
        if (sel.src === "email" && !raw && !clip(subject.value, 300)) return fail("Add the sender's address or the subject, so the email can be found.");
        if (sel.src === "email" && raw && !addr) return fail("That sender doesn't look like an email address.");
        const siteUrl = sel.src === "web" ? parseSite(site.value) : "";
        if (sel.src === "web" && clip(site.value, 2048) && !siteUrl) return fail("That doesn't look like a web address. Copy it from the address bar.");
        if (!sel.pw) return fail("Tell us whether you typed your password.");
        const label = (SOURCES.find((s) => s[0] === sel.src) || [])[1] || sel.src;
        const d = opts.details || {};
        const report = {
          url: location.href,
          blockedReason: clip(opts.reason, 500),
          rule: clip(d.rule || "", 200),
          referrer: clip(document.referrer, 2048),
          source: {
            type: sel.src, label, sender: raw, senderAddress: addr,
            subject: sel.src === "email" ? clip(subject.value, 300) : "",
            receivedAround: "",
            sharedBy: sel.src === "sharedfile" ? clip(sharedBy.value, 200) : "",
            site: siteUrl,
            note: "Reported from the warning banner",
          },
          enteredPassword: sel.pw,
          timestamp: new Date().toISOString(),
        };
        sendBtn.disabled = true;
        sendBtn.textContent = "Sending…";
        try {
          const r = await chrome.runtime.sendMessage({ type: "send_webhook", webhookType: "user_report", data: report });
          if (!r || !r.success) throw new Error((r && r.error) || "not sent");
          st.step = "thanks";
          st.report = report;
          render(host, opts, true);
        } catch (e) {
          sendBtn.disabled = false;
          sendBtn.textContent = `Send to ${company}`;
          fail(phone ? `That didn't send. Call ${company} on ${phone} instead.` : `That didn't send. Contact ${company} instead.`);
        }
      });

      return el("div", {},
        el("p", { class: "title" }, "Where did this link come from?"),
        el("div", { class: "form" },
          el("div", {}, srcRow), emailBox, sharedBox, siteBox,
          el("div", {}, el("p", { class: "q" }, "Did you type your password on this page?"), pwRow),
          err),
        el("div", { class: "acts" }, sendBtn,
          el("button", { class: "link", type: "button", on: { click: () => { st.step = "initial"; render(host, opts, true); } } }, "Cancel")));
    }

    sr.replaceChildren(el("style", { text: css(theme, compact) }),
      el("div", { class: "bar", role: compact ? "status" : "alert" }, brand, body, compact ? el("span") : close));
    // Let the page push its content below the banner after the browser lays it out.
    requestAnimationFrame(layout);
  }

  return { render };
})();
