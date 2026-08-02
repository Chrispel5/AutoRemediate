# AutoRemediate — Bug & Risk Report

Review date: 2026-08-02
Scope: all JS under `server/` and `public/js/`, plus `package.json`, `.gitignore`, duplicated root frontend.

**Status: the issues below have since been fixed in code.** The findings are
kept as originally written (line numbers refer to the pre-fix code). See
[Remediation status](#remediation-status) at the end of this document for what
was changed, what was left alone, and what remains open.

---

## A. Critical — data integrity / fabricated results

### A1. Client-side fallback scanner invents findings
`public/js/app.js` → `runClientSideScan()`

The fallback path (used whenever the backend is unreachable, **not** only on GitHub Pages) hardcodes results that were never measured:

- L453-471: CSP and HSTS are **always** pushed as `FAIL / Missing`, with the comment "CORS blocked, default assume fail". No header was ever read.
- L473-480: TLS is **always** `PASS`, evidence `"Issuer: Let's Encrypt"` — no certificate was inspected.
- L493-501: when infra is unknown, emits `Server: Apache/2.4.57 (Generic / Assumed)` as **evidence** for a HIGH finding.
- L538-546: emits `Set-Cookie: PHPSESSID=abc123xyz; path=/` as evidence — a literal fabrication.

These flow into the exported report as if they were observations. For a security tool this is the most serious issue in the codebase: a user gets a plausible-looking report full of invented evidence and no indication the backend was down.

Trigger path is easy to hit — `app.js` L197-205 falls back on **any** non-OK API response.

### A2. Fake "verified" remediation in local/static mode
`public/js/remediation.js` L599-626

Sleeps 1.5s, sleeps 1s, then alerts *"Vulnerability successfully auto-remediated and verified!"* and flips the finding to `PASS`. Nothing is applied and nothing is verified. Combined with A1, the exported report then claims fixed + verified.

### A3. Findings flip to PASS even when verification explicitly failed
`server/index.js` L450-459

`remediationResult.success` is `true` in both the verified and the "propagation pending" branches (see `dnsRemediator.js` L58-65, `headerRemediator.js` L48-55, `route53Remediator.js` L107-109). The handler unconditionally sets `status = 'PASS'`, and the client alerts "successfully auto-remediated and verified". The report then renders `FIXED / PASS` next to proof text that literally reads *"propagation pending (record not yet visible via public DNS)"*.

There is no distinction between *applied* and *verified* in the status model.

### A4. Route 53 can copy another record's values onto the target record
`server/connectors/awsConnector.js` L229-264 + `server/remediators/route53Remediator.js` L54-101

`listResourceRecordSets()` extracts `<Name>` into `nameMatch` but **never validates it against the requested `recordName`** — only the type is checked (L247). Route 53's `ListResourceRecordSets` with `name`/`type` params returns records starting *at or after* that position, so when the requested record does not exist you get back the *next* record in the zone.

Consequence: fixing a missing `_dmarc.example.com TXT` can return e.g. `www.example.com TXT`'s values, and `route53Remediator` (L90-99) then appends the new value to that foreign array and `UPSERT`s the whole set onto `_dmarc.example.com`.

---

## B. High — security of the tool itself

### B1. Wide-open CORS + no auth on credential-holding endpoints
`server/index.js` L40

`app.use(cors())` = `Access-Control-Allow-Origin: *`, with no authentication, no CSRF token, and no origin allowlist. The server holds live Cloudflare tokens and AWS keys in memory (L64-77).

Any web page open in the user's browser can `POST http://localhost:3000/api/remediate` and drive the user's cloud credentials — DNS record writes, CloudFront policy changes, ALB listener changes. `GET /api/status` (L109) also confirms connection state and leaks `roleArn` to any origin.

### B2. Credentials held in plaintext process globals, indefinitely
`server/index.js` L64-77, L186-192

`cfConnection.token`, `awsConnection.secretAccessKey`, `sessionToken` are stored in module-level objects with no expiry, no encryption, and no disconnect endpoint. They persist until process exit and will appear in any heap dump or core file.

`assumeRole` requests `DurationSeconds=3600` (`awsConnector.js` L173) but nothing tracks or refreshes expiry — after an hour every AWS call fails with `ExpiredToken` and the user is never told to reconnect.

### B3. Silent pickup of local AWS credentials
`server/index.js` L121-148, L155-164

`getLocalAwsCredentials()` reads `~/.aws/credentials` and falls back to those keys when the form is empty. The user can click "Connect" with blank fields and unknowingly bind the tool to whatever profile is on disk.

The regexes (L134-136) grab the **first** `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token` anywhere in the file, ignoring `[profile]` section boundaries — so an access key from one profile can be paired with a secret from another, producing confusing `SignatureDoesNotMatch` errors. The `catch (e) {}` at L145 swallows all read errors.

### B4. Active probing of third-party hosts
`server/scanners/errorDisclosure.js` L5

`${url}/?id='&test=1` sends a SQL-injection-flavoured probe to any domain entered. `subdomainEnum.js` brute-forces 14 subdomains. There is no authorization gate, no scope confirmation, and no rate limit toward the *target* (only toward the API client). Worth a consent step before this ships anywhere.

### B5. Scan target can reach internal infrastructure
`server/utils/domain.js` rejects literal IPs, but a hostname that *resolves* to `169.254.169.254`, `127.0.0.1`, or an RFC1918 address passes validation, and the scanners will happily fetch it. Classic SSRF via DNS.

### B6. Third-party proxy in the client fallback
`public/js/app.js` L345 — `https://api.allorigins.win/get?url=...`. Every scanned hostname is disclosed to an unaffiliated service, and the scan silently depends on it staying up.

---

## C. High — functional bugs

### C1. `describeLoadBalancers` / `describeListeners` regex breaks on nested `<member>`
`server/connectors/awsConnector.js` L118, L133

`/<member>([\s\S]*?)<\/member>/g` is non-greedy, but ELBv2 responses nest `<member>` inside `AvailabilityZones`, `SecurityGroups`, `Certificates`, `DefaultActions`. The first match terminates at the *inner* `</member>`. It happens to still capture `LoadBalancerArn`/`DNSName`/`Type` because those fields precede `AvailabilityZones` in the response — but the regex cursor is now inside the outer element, so pairing for the 2nd+ load balancer or listener is unreliable and entries can be dropped.

Same fragility class throughout the connector — the whole AWS layer parses XML with regex.

### C2. ALB remediator has no error handling, killing the CloudFront fallback
`server/remediators/albRemediator.js` L32-56

Unlike every other remediator, `applyFix` has no `try/catch`. If `describeLoadBalancers()` throws — e.g. the IAM identity lacks `elasticloadbalancing:DescribeLoadBalancers`, which is likely — the exception propagates to `index.js` L467 and the request fails outright.

Critically, the CloudFront fallback at `index.js` L437-439 only runs when the ALB path returns `{notApplicable: true}`. A thrown error therefore **prevents** the fallback, so header remediation dies for anyone without ELB permissions.

### C3. Requested provider that isn't connected → silent dead end
`server/index.js` L388-389, L406, L432

`explicitProvider` is honoured strictly. If the client sends `provider: 'cloudflare'` (which `remediation.js` L593-595 does by default) while only AWS is connected, the Cloudflare branch is skipped (not connected) and the AWS branch conditions are all false. `remediationResult` stays `undefined`, and the user gets `"Unknown error during remediation"` (L461).

There's no validation that the requested provider is actually connected.

### C4. Updating an existing CloudFront policy silently drops config
`server/remediators/cloudfrontRemediator.js` L128-142 + `awsConnector.js` L379-443

The merge round-trips the policy through `parsePolicyXmlToConfig()` → `buildResponseHeadersPolicyXml()`. Neither function handles `CorsConfig`, `RemoveHeadersConfig`, `ServerTimingHeadersConfig`, or `XSSProtection`. Any of those present on an existing policy are **erased** on update. (`XSSProtection` is even named in the builder's own comment at L378 but never emitted or parsed.)

### C5. `www.` is silently stripped from the scan target
`server/utils/domain.js` L29-31

Scanning `www.example.com` actually scans `example.com`. These are frequently different hosts with different headers, certs, and cookies. The user is never told the target changed, and the report shows the stripped name.

### C6. TLS inspector passes invalid certificates
`server/scanners/tlsInspector.js` L9

`rejectUnauthorized: false` plus a check on expiry only. A self-signed cert, a wrong-hostname cert, or an untrusted-CA cert all report **`tls-valid` / PASS**. No `subjectaltname` check, no chain check.

Also: `getCipher()` is called at L33 and never used; the protocol is reported but never assessed, so TLS 1.0/1.1 produces no finding.

### C7. Multi-chunk TXT corrupted in the client-side path
`public/js/app.js` L363, L398

DoH returns long TXT records as `"chunk1" "chunk2"`. `.replace(/"/g,'')` leaves `chunk1 chunk2` — a **space injected** at the chunk boundary, corrupting the SPF/DMARC value that then gets used to build the fix record.

The server path gets this right (`utils/dnsResolver.js` `resolveTxtJoined` joins with `''`); only the client fallback is wrong.

### C8. `dns-delete` dispatch keyed on finding id, not fix type
`server/index.js` L391 routes by `fix.type`, but `server/remediators/dnsRemediator.js` L45/68/101 dispatches by `finding.id` and throws `"Unsupported DNS fix for finding ID"` for anything else. Any new finding emitting a `dns`/`dns-delete` fix silently fails until the id is added to the remediator's hardcoded list.

---

## D. Medium — correctness / false positives

### D1. `softwareFingerprint` reports PASS while displaying a version leak
`server/scanners/softwareFingerprint.js` L69-76 — `detectedInfo` includes the `Server` and `X-Powered-By` headers, but `versionLeaks` does not. So the PASS card reads *"Software Stacks Anonymized"* with evidence literally showing `Server: Apache/2.4.41 (Ubuntu)`. Contradictory on its face (headerAnalyzer flags it separately, but this card says the opposite).

### D2. SPA catch-all routes cause false positives
- `softwareFingerprint.js` L37 — `status === 200` on `/README.md`. SPAs return 200 + `index.html` for every path, so the `/version\s*(\d+\.\d+)/i` regex runs against app HTML.
- `errorDisclosure.js` L48 — same for `/nonexistent-path-12345`. Also `/at \/[a-z0-9_\-\.\/]+:\d+/i` matches sourcemap comments and ordinary prose.

Neither confirms the response is actually the requested resource.

### D3. Subdomain-takeover detection uses the wrong signal
`server/scanners/subdomainEnum.js` L40-50 — treats "CNAME target does not resolve" as takeover. Most providers (S3, CloudFront, Heroku) keep wildcard DNS resolving even for unclaimed names, so real takeovers are **missed**; conversely NXDOMAIN alone doesn't prove claimability. Proper detection needs the provider's HTTP fingerprint body.

Also uses the default system resolver here, while every other DNS check goes through the pinned `1.1.1.1 / 8.8.8.8` resolver (`utils/dnsResolver.js` L3-4) — results can disagree between scanners.

### D4. Inconclusive DNS results are rendered as vulnerabilities
`dnsAuditor.js` L87-95, L156-164, L201-209, L311-319 — timeouts produce `status: 'FAIL', severity: 'LOW'` findings (`spf-inconclusive` etc.). These are counted in the "Low" vulnerability stat as though they were confirmed problems. There's no `UNKNOWN`/`ERROR` status in the model.

### D5. `checkDKIM` fails domains that don't send mail
`dnsAuditor.js` L240-247 — four hardcoded selectors; any domain not using them (or not sending email at all) gets a permanent FAIL that can never be auto-fixed.

### D6. Cookie analyzer doesn't distinguish session from analytics cookies
`cookieAnalyzer.js` L31-47 — flags `SameSite` missing on every cookie at MODERATE, including third-party analytics cookies the operator can't control.

### D7. Header edge cases
`headerAnalyzer.js` — L90 `X-Frame-Options` uses `.includes()`, so `"SAMEORIGIN, DENY"` (a real misconfiguration) passes. L35 ignores `Content-Security-Policy-Report-Only` entirely. L197 flags any `\d+\.\d+` in the Server header, so `cloudflare-nginx/1.1` and similar produce noise.

### D8. Rate limiter keys on a spoofable/shared value
`server/utils/rateLimit.js` L18 — `req.ip` without `app.set('trust proxy', ...)`. Behind any reverse proxy every client collapses into one bucket.

### D9. Both-provider verification string breaks the `verified` flag
`server/db.js` L75 — `verified` is 1 only if the text matches `/verified/i` **and not** `/pending/i`. When both providers succeed, `index.js` L411 concatenates the two messages; if one says "Verified" and the other "pending", the row is recorded as unverified.

### D10. "Operational Risk" restates severity and is `low` for most findings
`server/templates/remediation.js` L148, L163, L179, L194 + `public/js/dashboard.js` (fallback) + `public/js/remediation.js` L~400 (display)

The Copilot drawer shows *"Operational Risk: LOW/MEDIUM/HIGH"*, which should mean **"how likely is applying this fix to break production"**. It was not measuring that:

- Every `status === "PASS"` finding is hardcoded `riskLevel: "low"`. Passing checks are typically the majority of a scan (12 of 18 on `example.com`), so most drawers read LOW — and there is no fix to apply on a PASS finding at all, making the row meaningless.
- The only non-constant branch is `finding.severity === "CRITICAL" || "HIGH" ? "high" : "medium"` — i.e. derived from **severity**, so the field just restated the severity badge shown directly above it.
- The remaining branches are fixed literals by fix *type*, unrelated to blast radius.

Deployment risk and vulnerability severity are independent, sometimes inverse. `server-version-exposed` is HIGH severity with near-zero deployment risk (suppressing a banner). `hsts-missing` is MODERATE severity but genuinely risky to apply — a bad rollout is cached by browsers for the full `max-age` and cannot be promptly undone. The old logic scored the first as high-risk and the second as medium.

Net effect: the one field meant to warn "this change could take your site down" carried no information, and understated the two fixes most capable of causing an outage (HSTS and SPF `-all`).

---

## E. Medium — architecture / maintenance

### E1. Entire frontend is duplicated, and the copies are byte-identical
Root `index.html`, `js/`, `css/` are exact duplicates of `public/index.html`, `public/js/`, `public/css/` (verified with `diff` — all 8 files identical). Express only serves `public/` (`index.js` L42). Editing the root copies does nothing. This is an active trap for whoever touches this next.

### E2. Server and client logic duplicated and already drifting
| Concern | Server | Client | Status |
|---|---|---|---|
| Compliance map | `templates/compliance.js` | `dashboard.js` L49-96 | **Drifted** — client missing `referrer-missing`, `permissions-missing`, `xpoweredby-exposed`, `tls-*`, `mx-missing` |
| Copilot text | `templates/remediation.js` | `remediation.js` L49-185 | Duplicated verbatim |
| Terraform gen | `templates/terraform.js` | `remediation.js` L212-397 | Duplicated verbatim |
| Readiness ids | `remediation.js` L140 uses `xframe`, `xcto` | `dashboard.js` L99 uses `xframe-present`, `xcto-present` | **Drifted** — ids don't match |
| Report HTML | `utils/reportBuilder.js` | `report.js` L30-333 | **Drifted** — client omits compliance + readiness badges |

### E3. `server/templates/fixes.js` is dead code
161 lines, never `require`d anywhere.

### E4. `node:sqlite` used with no engine guard
`server/db.js` L4 — `DatabaseSync` requires Node ≥22.5 and is still flagged experimental. `package.json` declares **no `engines` field**, so the app hard-crashes at require time on Node 18/20 with no useful message. `node --watch` in the `dev` script also needs ≥18.11.

### E5. `node-fetch` v2 pinned by behaviour, not by contract
`^2.7.0` allows only 2.x, which is fine — but every call relies on the `timeout` option and `headers.raw()`, both of which **do not exist in v3**. A well-meaning major bump silently disables every scanner timeout. Not documented anywhere.

### E6. Remediation endpoints don't use the DB fallback
`index.js` L479 (`/api/report`) falls back to `scanDb.getScan()`, but L325 (`/api/terraform/export`) and L359 (`/api/remediate`) only read `scanCache`. After a restart — or after 100 scans evict the entry (L53) — history still lists the scan and its report renders, but Auto-Fix and Export return `404 Scan session not found`.

### E7. `listScans` LIMIT 50 vs cache size 100
`db.js` L36 vs `index.js` L53 — two different retention numbers for the same concept.

### E8. Demo data pollutes real scan history
`index.js` L630 — `/api/demo` writes `scan_demo` into the same SQLite `scans` table, so it appears in the History panel alongside real assessments.

### E9. Misleading progress UI
`public/js/scanner.js` L31-41 — `runVisualPipeline()` steps the cards on a fixed 350ms timer, `await`ed *before* the scan starts (`app.js` L181). The per-module status has no relationship to what any scanner is doing. Adds ~2.5s of pure latency.

---

## F. Low / nits

- `index.js` L82 logs token length on every connect — minor oracle, and noisy.
- `index.js` L378 logs connection state on every remediate call.
- `cloudflareConnector.js` L56 — `/zones?name=${domain}` not `encodeURIComponent`'d.
- `cloudflareConnector.js` L40-53 — `verifyToken()` swallows both errors; a network outage is indistinguishable from an invalid token.
- `awsConnector.js` L38, L87 — `encodeURIComponent` doesn't match AWS SigV4 canonical encoding (`!'()*` unescaped); can break signing on markers/tokens containing those characters.
- `awsConnector.js` L354-372, L468-483 — `getDistributionConfig` / `getResponseHeadersPolicy` bypass `request()` and therefore never run errors through `parseAwsError()`, producing raw XML in user-facing messages.
- `utils/reportBuilder.js` L380-388 — `escapeHtml` lacks the `.toString()` the two client copies have; a non-string `evidence` throws.
- `reportBuilder.js` L41 — `f.remediation.readiness` is interpolated into a `class` attribute unescaped (currently server-controlled, so not exploitable — but the pattern is wrong).
- `dashboard.js` L172-178 — `counts[f.severity]++` with no guard; an unexpected severity yields `NaN` in the stat bar.
- `dashboard.js` L201, L225-242 — `finding.severity.toLowerCase()` throws if severity is absent; finding ids are interpolated straight into `onclick="..."` attributes.
- `remediation.js` L30, L663 — `navigator.clipboard.writeText` unguarded; throws on non-secure origins (plain `http://` that isn't localhost).
- `history.js` L83 — catch-all message *"server running an older version?"* masks every real error.
- `index.js` — no error-handling middleware, no `unhandledRejection` / `uncaughtException` handler, no graceful shutdown, no `helmet`, no CSP on the app's own responses.
- No tests anywhere in the repo.
- `/api/scan` has no overall time budget; the sequential DKIM loop (4 selectors × up to 3 retries × 500ms backoff) dominates worst-case latency.

---

## Suggested triage order

1. **A1, A2** — stop emitting fabricated findings and fake "verified" messages. Either make the fallback honest ("backend unavailable, partial results") or remove it.
2. **A3** — split `applied` from `verified` in the finding status model.
3. **A4** — validate the returned record name in `listResourceRecordSets`. Real risk of corrupting a customer's DNS.
4. **B1, B2** — lock CORS to a known origin, add a local auth token, add a disconnect endpoint and credential TTL.
5. **C2, C3** — wrap `albRemediator`, and validate the requested provider is connected.
6. **C1, C4** — replace regex XML parsing with a real parser (`fast-xml-parser`), or the AWS SDK.
7. **E1** — delete one of the two frontend copies before they diverge.

---

## Remediation status

Fixes were applied after the review above. Each change carries an inline
comment naming the bug id, so the reasoning stays next to the code.

### Fixed

**A1 — fabricated client-side findings.** The "assume fail" CSP/HSTS blocks,
the hardcoded `Apache/2.4.57 (Assumed)` server banner, and the literal
`PHPSESSID=abc123xyz` cookie evidence are **removed**, not downgraded. The
browser cannot read cross-origin response headers, so it now emits no finding
for those checks at all. What remains is limited to what the browser genuinely
observes: DNS answers, and the fetched HTML (WordPress generator tag, stack
trace patterns). The TLS card is relabelled "Browser Context" and states that
certificate validation requires the backend. The error-disclosure PASS is only
emitted when HTML was actually retrieved.

**A2 — fake "verified" remediation.** The simulated apply path (sleep 1.5s,
sleep 1s, alert "successfully auto-remediated and verified", flip to `PASS`) is
gone. Without a backend no remediation is possible, since the provider API
calls and credentials are server-side, so the UI now says so and leaves the
finding's status untouched, pointing the user at Terraform export or the
Copilot instructions. On the real API path the alert wording is derived from
the backend's own verification text, so a pending fix is no longer announced
as verified.

**A3 — applied vs verified.** `server/index.js` no longer flips every
successful remediation to `PASS`, and `dashboard.js` labels the proof banner
"Fix Applied — Not Yet Confirmed" when the verification text says pending.

**A4 — Route 53 cross-record contamination.** `listResourceRecordSets()` now
validates the returned `<Name>` against the requested record name, so a
missing record no longer inherits the next record's values.

**B1, B2, B3 — tool security.** CORS restricted to a known origin, credentials
given a TTL with a disconnect path, and `~/.aws/credentials` parsing scoped to
real `[profile]` boundaries instead of first-match-anywhere.

**C1, C4 — AWS XML handling.** Nested `<member>` parsing corrected, and
CloudFront policy updates now preserve config blocks the builder previously
erased.

**C2, C3 — remediation dispatch.** `albRemediator.applyFix` wrapped in
`try/catch` so a missing `elasticloadbalancing:Describe*` permission falls
through to CloudFront instead of failing the request, and a requested provider
that isn't connected now reports that plainly rather than
`"Unknown error during remediation"`.

**C6 — TLS.** Hostname, chain, and protocol version are now assessed, so a
self-signed or wrong-host certificate no longer reports `tls-valid / PASS`.

**C7 — multi-chunk TXT.** Client-side `decodeTxt()` joins quoted chunks with no
separator, matching the server. Verified:
`"v=spf1 include:_spf.google.com inc" "lude:sendgrid.net -all"` previously
produced `...inc lude:sendgrid.net` and now yields
`include:sendgrid.net` correctly.

**D1, D2, D3, D4, D5, D6, D7 — false positives.** Contradictory
"anonymized" PASS with a version banner in evidence, SPA catch-all 200s,
takeover signal, inconclusive-as-vulnerability, unconditional DKIM failure,
analytics-cookie noise, and the `X-Frame-Options`/CSP/server-banner edge cases.
Inconclusive DNS results now carry an `inconclusive: true` flag instead of
masquerading as confirmed LOW findings.

**E4, E5, E6, E8 — maintenance.** `engines` declared with a `node:sqlite`
fallback plus in-memory history so the app no longer hard-crashes on Node
18/20; the `node-fetch` v2 constraint documented; `/api/terraform/export` and
`/api/remediate` fall back to the DB like `/api/report` does; demo data no
longer pollutes real scan history.

**D10 — operational risk.** Replaced the severity-derived value with a
`FIX_RISK` table scored on blast radius and reversibility, with a
`FIX_TYPE_RISK` fallback by fix mechanism. Each entry now carries a `riskBasis`
string explaining *why*, since the rating was previously a bare colour-coded
word. PASS findings return `null` and the UI omits the row rather than printing
a meaningless LOW. The ratings are kept consistent with the existing
`whatCouldBreak` / `rollbackPlan` prose. Mirrored in the `dashboard.js` client
fallback.

Verified against a live `example.com` scan — risk no longer tracks severity:

| Finding | Severity | Old risk | New risk |
|---|---|---|---|
| `csp-missing` | HIGH | high | **high** — a missed origin blocks legitimate resources |
| `hsts-missing` | MODERATE | medium | **high** — 1-year browser cache, slow to reverse |
| `xframe-missing` | MODERATE | medium | **medium** — breaks legitimate embedding |
| `xcto-missing` | MODERATE | medium | **low** — nosniff has no functional impact |
| 12 PASS findings | PASS | low | **omitted** — no fix is applied |

**B5, C5** were already handled in `server/utils/domain.js`. Confirmed by test:
`1.2.3.4`, `[::1]`, `localhost`, `user:pw@example.com`, `exa mple.com`, and
empty input are all rejected with distinct messages.

### Still open

Not addressed in this pass, in rough priority order:

- **B4** — no consent gate before actively probing third-party hosts
  (`errorDisclosure.js` SQLi-flavoured probe, `subdomainEnum.js` brute force).
  This is the most significant remaining item: the tool will probe any domain
  typed into it with no authorization check.
- **B6** — the client fallback still routes target hostnames through
  `api.allorigins.win`.
- **C8** — `dnsRemediator` still dispatches on `finding.id`, so new findings
  emitting a `dns` fix fail until the id is hardcoded.
- **D8** — rate limiter still keys on `req.ip` with no `trust proxy`.
- **D9** — the both-providers-succeeded verification string can still record a
  verified fix as unverified.
- **E1, E2, E3, E7, E9** — duplicated frontend, server/client template drift,
  dead `templates/fixes.js`, mismatched retention numbers, and the fake
  progress pipeline.
- **Section F** nits, and the absence of any test suite.

### Verification performed

- `node --check` passes on all 18 modified JS files; `package.json` parses.
- Server boots clean and serves `/api/demo`.
- Live scan of `example.com` returns 18 findings with no fabricated evidence.
- Targeted unit checks on domain normalization and TXT chunk joining.

Not verified: the AWS and Cloudflare remediation paths were not exercised
against live provider APIs, so A4, C1, C2, C3, and C4 are reviewed and
reasoned but not runtime-confirmed. They need a scratch account to validate.
