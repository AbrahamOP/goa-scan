<p align="center">
  <img src="store/banner.png" alt="Goa Scan — grades the security of the page you're on, A to F" width="100%">
</p>

<p align="center">
  <a href="https://github.com/AbrahamOP/goa-scan/actions/workflows/ci.yml"><img src="https://github.com/AbrahamOP/goa-scan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Manifest-V3-1D9E75" alt="Manifest V3">
  <img src="https://img.shields.io/badge/dependencies-0-1D9E75" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/telemetry-none-1D9E75" alt="No telemetry">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-534AB7" alt="MIT license"></a>
</p>

<h3 align="center">A security audit of any web page, in one click.<br>Graded A to F, explained, and 100&nbsp;% local.</h3>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#install">Install</a> ·
  <a href="#privacy">Privacy</a> ·
  <a href="README.fr.md">Français</a>
</p>

<br>

<p align="center">
  <img src="store/showcase.png" alt="Three Goa Scan popups: grade and findings, decoded TLS certificate, secrets found in JavaScript" width="100%">
</p>

<br>

Goa Scan reads what a page sends to your browser — certificate, headers, cookies, API
calls, JavaScript — and turns it into a grade, a list of findings ranked by severity,
and a fix for each one. Built for developers checking their own site, and for
pentesters and bug bounty hunters who want passive recon without leaving the tab.

## Features

<table>
  <tr>
    <td width="33%" valign="top"><b>TLS certificate</b><br><sub>Full chain decoded, expiry, weak keys, TLS version and cipher. Warns when a site's certificate changes.</sub></td>
    <td width="33%" valign="top"><b>Security headers</b><br><sub>CSP, HSTS, clickjacking, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORS.</sub></td>
    <td width="33%" valign="top"><b>Cookies</b><br><sub>Secure, HttpOnly, SameSite. Values are never read.</sub></td>
  </tr>
  <tr>
    <td valign="top"><b>API calls</b><br><sub>Every fetch, XHR and WebSocket call grouped by endpoint, with status and auth scheme.</sub></td>
    <td valign="top"><b>Secrets in JavaScript</b><br><sub>~30 key formats: AWS, Stripe, GitHub, OpenAI, Supabase… Masked on detection.</sub></td>
    <td valign="top"><b>Endpoints &amp; parameters</b><br><sub>Paths and parameter names hidden in the bundles, cross-checked with real calls.</sub></td>
  </tr>
  <tr>
    <td valign="top"><b>Vulnerable libraries</b><br><sub>Embedded retire.js database, ~485 CVEs, no network call.</sub></td>
    <td valign="top"><b>Page content</b><br><sub>Mixed content, insecure forms, scripts without SRI, tokens in storage.</sub></td>
    <td valign="top"><b>Active mode</b> <sub>(opt-in)</sub><br><sub>Exposed <code>.git</code> / <code>.env</code>, public OpenAPI docs, CAA, DNSSEC, SPF, DMARC.</sub></td>
  </tr>
</table>

Grade on the toolbar icon, full-page report, export to Markdown, PDF or JSON.

<details>
<summary><b>Full list of checks</b></summary>
<br>

- **Certificate** — subject, issuer, validity, key, signature, SHA-256 fingerprint, SANs,
  DV/OV/EV, SCTs; expired or expiring, hostname mismatch (wildcards included),
  self-signed, SHA-1/MD5, RSA < 2048 / EC < 256, lifetime > 398 days, expired
  intermediate; TLS 1.0/1.1, static RSA, CBC, Certificate Transparency; `ERR_CERT_*`
  errors. Fingerprint pinned per site: a change that does not look like a renewal
  raises an alert.
- **Transport** — HTTPS, HTTP → HTTPS redirect, HSTS (max-age, includeSubDomains,
  preload), active and passive mixed content, cleartext WebSocket.
- **Headers** — CSP (missing, report-only, `unsafe-inline`, `unsafe-eval`, wildcards,
  `object-src`, `base-uri`, multiple policies), `frame-ancestors` / X-Frame-Options,
  `nosniff`, Referrer-Policy, Permissions-Policy, COOP, CORS `*`, deprecated
  X-XSS-Protection. Raw headers and redirect chain.
- **Exposure** — server version, `X-Powered-By`, `meta generator`, vulnerable JS
  libraries, `security.txt`.
- **Cookies** — Secure, HttpOnly on session cookies, SameSite.
- **Content** — password on HTTP, form posted in clear or cross-site, third-party
  scripts without SRI, unsandboxed third-party iframes, tokens in Web Storage (key
  names only), sensitive HTML comments, exposed e-mails, inline scripts and `on*`
  handlers.
- **API** — method, endpoint (`/users/123` → `/users/:id`), status, response type,
  auth scheme; tokens or keys in URLs, HTTP Basic, 5xx; public OpenAPI/Swagger docs
  (active mode).
- **JavaScript code** — secrets (AWS, Stripe, GitHub, GitLab, OpenAI, Anthropic,
  Google, Slack, Discord, Telegram, SendGrid, Twilio, Mailgun, npm, Hugging Face,
  Shopify, private keys, JWTs…), public-by-design keys told apart; endpoints and
  parameters mentioned in the code, sensitive paths (`/admin`, `/actuator`…).
- **Network & stack** — requests, third-party domains, trackers, server IP; server,
  CDN, CMS and framework detection with versions.

</details>

<details>
<summary><b>How the grade works</b></summary>
<br>

100 minus a penalty per finding — critical 25, high 12, medium 6, low 2, info 0.
A page served over plain HTTP is capped at 40.

| A | B | C | D | E | F |
|:-:|:-:|:-:|:-:|:-:|:-:|
| ≥ 90 | ≥ 75 | ≥ 60 | ≥ 45 | ≥ 30 | < 30 |

</details>

## Install

1. Download or clone this repository.
2. Open `chrome://extensions` and turn on **Developer mode**.
3. **Load unpacked** → select the folder, then pin Goa Scan.

Chrome, Edge, Brave, Opera and other Chromium browsers, version 116 or later.
The interface is in French for now.

## Privacy

No account, no server, no telemetry. In passive mode, the only requests Goa Scan sends
go **to the site you are analysing**. Cookie values and secrets are masked and never
exported in clear. External tools (SSL Labs, VirusTotal…) only receive the domain when
you click their link. Details in [PRIVACY.md](PRIVACY.md).

<details>
<summary><b>Permissions</b></summary>
<br>

| Permission | Why |
|---|---|
| `webRequest` + `<all_urls>` | Read the page's response headers and list its requests. Nothing is blocked or modified. |
| `scripting` | Inspect the DOM of the tab at analysis time. |
| `cookies` | Read cookie attributes, not their values. |
| `storage` | Per-tab capture and pinned certificate fingerprints, on your device. |
| `debugger` *(optional)* | The only way Chrome exposes a TLS certificate to an extension. |

Chrome keeps certificates away from extensions and closes the DevTools `Security`
domain to them. Goa Scan attaches to the tab for ~0.5 s, calls
`Network.getCertificate`, decodes the DER chain locally, reads `securityDetails` from
a cookieless `HEAD` probe, then detaches. Chrome briefly shows a "started debugging"
bar. Without this permission, everything else works.

</details>

<details>
<summary><b>Limitations</b></summary>
<br>

- A rejected certificate shows Chrome's own error page, which nothing can attach to:
  only the `ERR_CERT_*` code is known and the grade drops to F.
- If the page's CSP blocks the probe, only the certificate chain is shown.
- Pages loaded before the extension or restored from cache: hit *Reload*.
- `chrome://` pages, the Chrome Web Store and the PDF viewer cannot be inspected.
- Single-page apps keep the capture of the first document.

</details>

<details>
<summary><b>Development</b></summary>
<br>

Vanilla JavaScript, no dependency, no build step. Rules are pure functions tested
under Node; end-to-end tests drive a real Chromium.

```bash
node --test tests/*.test.js     # unit tests
node tools/package.mjs          # store-ready zip in dist/
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

</details>

<br>

<p align="center">
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="LICENSE">MIT License</a>
  <br><br>
  <sub>Vulnerability data from <a href="https://github.com/RetireJS/retire.js">retire.js</a> (Apache-2.0).<br>
  Built by GoaCloud — <i>the studio for sovereign tools.</i></sub>
</p>
