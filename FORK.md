# Guardian Browser Protection (modified build of Check by CyberDrain)

This is a modified version of [Check by CyberDrain](https://github.com/CyberDrain/Check), licensed under **AGPL-3.0** (see `LICENSE`).
Source for every published build is in this repository: branch `main`, one GitHub Release per build.

- **Upstream:** CyberDrain/Check commit `6e4f041` (version 1.3.0).
- **Detection:** upstream detection logic and rules are unchanged.
- **Extension ID:** `congdhhoabelnjdjpfdgifhnokfeledl` (fixed by the signing key, which is not in this repository).
- **Update URL:** `https://github.com/IAPW-NoZeroDay/guardian-browser-protection/releases/latest/download/updates.xml`

## Changes from upstream

| Change | Files |
|---|---|
| Generic webhook: optional managed `headers` (e.g. a shared-secret auth header; protocol headers can't be overridden) and `staticFields`, sent as `payload.fields` | `scripts/modules/webhook-manager.js`, `config/managed_schema.json` |
| Block page: optional "Where did this link come from?" form (email sender and subject, shared file, chat, text message, website) and "Did you type your password?", with a call-us box using `customBranding.supportPhone`. Sent as a new `user_report` webhook event (known fields only, length-capped). Shown only when the managed `genericWebhook.events` includes `user_report` | `blocked.html`, `scripts/source-report.js`, `scripts/modules/webhook-manager.js`, `config/managed_schema.json`, `manifest.json` |
| Warning banner redesign: plain-language titles, solid high-contrast colours, no emoji, rendered in a closed shadow root (page CSS and scripts can't touch it). Report-first: "Report it to <company>" opens the same report form inside the banner (email sender/subject, who shared a file, or which website), and "Leave this page" becomes the main action only after reporting. Company name and phone come from managed `customBranding` | `scripts/banner-ui.js` (new), `scripts/content.js`, `manifest.json`, `scripts/source-report.js` |
| Bug fix: detections reach the generic webhook when CIPP reporting is off. Upstream returns early in `sendCippReport` unless `enableCippReporting` and `cippServerUrl` are set | `scripts/content.js` |
| Webhook hardening: content scripts get the generic webhook as `{ enabled, configured, events }` without its URL or headers; `user_report` is rate-limited (5 per 10 minutes), tagged `reportedFrom`, and from the banner its `url` comes from the browser; generic webhook calls send no cookies or referrer, don't follow redirects and time out after 15 s; logs omit the URL's query string | `scripts/background.js`, `scripts/modules/webhook-manager.js` |
| Extension name, description and toolbar title | `manifest.json` |
| CI: CyberDrain's store-publishing, release and issue-bot workflows removed; one read-only `ci.yml` (syntax check, JSON check, tests) | `.github/workflows/ci.yml`, `tests/webhook-manager.test.js` |
| Build tools: dependency-free CRX3 packer and build script (stages the store files, stamps `1.3.0.<build>`, writes `updates.xml`) | `fork-build/` |

## Building

```powershell
.\fork-build\Build-Extension.ps1 -NewKey                          # once: creates the signing key, prints the extension ID
.\fork-build\Build-Extension.ps1 -Build 2 -UpdateBaseUrl 'https://github.com/IAPW-NoZeroDay/guardian-browser-protection/releases/download/v1.3.0.2'
```
Requires Node.js and PowerShell 7.

## Test locally

`chrome://extensions` (or `edge://extensions`) → Developer mode → **Load unpacked** → this folder.
