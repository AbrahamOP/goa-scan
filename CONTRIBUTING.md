# Contributing to Goa Scan

Thanks for helping. Issues and pull requests can be written in English or French.

## Reporting a false positive or a missed issue

Open an issue with:

- the URL (or a minimal HTML page reproducing the case),
- what Goa Scan reported and what you expected,
- your browser and version.

Never paste a real secret, token or cookie value in an issue — Goa Scan masks them,
please do the same.

## Adding a check

Most rules live in `checks.js` (headers, cookies, content, API), `secrets.js`
(JavaScript secrets, endpoints, parameters) and `cert.js` (certificate decoding). They
are **pure functions**: no DOM, no `chrome.*`, so they run under Node.

1. Add the rule with a severity (`critical`, `high`, `medium`, `low`, `info`), a title,
   an explanation and a fix.
2. Add a test in `tests/*.test.js`. For secret formats, build fake tokens at runtime
   (`'AK' + 'IA' + …`) so that GitHub push protection does not flag the test file.
3. Check for false positives on a few real, popular sites before opening the PR.

## Running the tests

```bash
node --test tests/*.test.js
```

End-to-end tests drive a real Chromium through Puppeteer:

```bash
npm i --no-save puppeteer-core
python3 tests/e2e/fixture.py &            # local trap page
node tests/e2e/e2e.mjs
python3 tests/e2e/fixture-active.py &     # API, secrets and OpenAPI fixture
node tests/e2e/e2e-api.mjs
```

Set `CHROME=/path/to/chromium` if it is not in `/usr/bin/chromium`.

## Ground rules

- **No dependency, no build step.** The extension ships as plain files.
- **Nothing leaves the browser.** No analytics, no remote code, no call to a third
  party in passive mode. A PR that breaks this will not be merged.
- **Never read or store sensitive values** (cookie values, tokens, secrets) in clear.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`…).
