import { test } from "node:test";
import assert from "node:assert/strict";
import { WebhookManager } from "../scripts/modules/webhook-manager.js";

const configWith = (genericWebhook) => ({ getConfig: async () => ({ genericWebhook }) });

test("managed headers: protocol headers, bad names and control characters are dropped", () => {
  const wm = new WebhookManager(configWith({}));
  const out = wm.safeHeaders({
    "x-guardian-key": "s3cret",
    "Content-Type": "text/plain",
    "X-Webhook-Type": "spoofed",
    "x-webhook-anything": "spoofed",
    Cookie: "a=b",
    "Bad Name": "x",
    "x-crlf": "a\r\nInjected: 1",
    "x-nul": "a\u0000b",
    "x-unicode": "café",
  });
  assert.deepEqual(out, { "x-guardian-key": "s3cret" });
});

test("static fields: plain key/values only, capped in count and length", () => {
  const wm = new WebhookManager(configWith({}));
  const many = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, "v"]));
  assert.equal(Object.keys(wm.safeObject(many)).length, 32);
  assert.deepEqual(wm.safeObject({ device: "PC-1", n: 2, obj: { a: 1 }, "bad key": "x" }), { device: "PC-1", n: "2" });
  assert.equal(wm.safeObject({ long: "x".repeat(600) }).long.length, 512);
  assert.deepEqual(wm.safeObject(["a"]), {});
});

test("user_report payload keeps known fields only, with enums and length caps", () => {
  const wm = new WebhookManager(configWith({}));
  const p = wm.buildUserReportPayload({
    reportedFrom: "somewhere-else",
    url: "https://evil.example/" + "a".repeat(3000),
    enteredPassword: "maybe",
    extra: "dropped",
    source: { type: "<img src=x>", sender: "s".repeat(400), note: "n".repeat(2000), extra: "dropped" },
  });
  assert.equal(p.reportedFrom, "unknown");
  assert.equal(p.url.length, 2048);
  assert.equal(p.enteredPassword, "unknown");
  assert.equal(p.source.type, "unknown");
  assert.equal(p.source.sender.length, 320);
  assert.equal(p.source.note.length, 1000);
  assert.equal("extra" in p, false);
  assert.equal("extra" in p.source, false);
});

test("log lines never include the webhook's query string (shared key)", () => {
  const wm = new WebhookManager(configWith({}));
  assert.equal(wm.redactUrl("https://hooks.example.com/webhooks/abc?k=SECRET"), "https://hooks.example.com/webhooks/abc");
  assert.equal(wm.redactUrl("not a url"), "(invalid URL)");
});

test("generic webhook: sends managed headers and static fields, refuses redirects", async () => {
  const wm = new WebhookManager(
    configWith({
      enabled: true,
      url: "https://hooks.example.com/h?k=1",
      events: ["user_report"],
      headers: { "x-guardian-key": "s3cret", "X-Webhook-Type": "spoofed" },
      staticFields: { device: "PC-1" },
    })
  );
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, statusText: "OK" };
  };
  try {
    const r = await wm.sendWebhook("user_report", { source: { type: "email" } }, { extensionVersion: "1.3.0.1" });
    assert.equal(r.success, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(calls.length, 1);
  const { init } = calls[0];
  assert.equal(init.redirect, "error");
  assert.equal(init.credentials, "omit");
  assert.equal(init.headers["x-guardian-key"], "s3cret");
  assert.equal(init.headers["X-Webhook-Type"], "user_report");
  const body = JSON.parse(init.body);
  assert.deepEqual(body.fields, { device: "PC-1" });
  assert.equal(body.data.source.type, "email");
});

test("events not listed in the policy are not sent", async () => {
  const wm = new WebhookManager(configWith({ enabled: true, url: "https://hooks.example.com/h", events: [] }));
  const r = await wm.sendWebhook("user_report", {}, { extensionVersion: "1" });
  assert.equal(r.skipped, true);
});
