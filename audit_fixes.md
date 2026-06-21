# ThreatOrbit‑V2 — Deep Code Review & Weakness Report

**Repository:** `github.com/Sami9211/ThreatOrbit-V2` (branch: `main`)
**Reviewed:** full clone of `main` — ~28,000 lines of Python across `threat_api`, `log_api`, and `dashboard_api`, plus ~37,000 lines of TypeScript/React in `frontend`, the CI workflows, Helm chart, Dockerfiles, and docs.
**Method:** static read of source (no execution), pattern sweeps for dangerous constructs, and per‑module inspection of the security‑critical code paths.
**Audience note:** this is written to be useful for two things at once — *making the project stronger*, and *making you bulletproof when an interviewer opens this repo and starts poking*.

---

## 1. Headline verdict (read this first)

This is **not** a typical junior portfolio project, and it would be a mistake to treat the findings below as "beginner mistakes." The codebase is large, security‑aware, and in several places does things that most working teams get wrong (XML‑signature‑wrapping defence, constant‑time secret comparison, fail‑closed RBAC, per‑install persisted secrets, digest‑pinned base images, a real CI matrix with `pip-audit` gating). Credit where due is in §2 — and you should lean on it.

The weaknesses fall into a few honest buckets:

1. **The app is written as if it runs in one process, but it's deployed multi‑process.** This is the single most important theme. Several features keep state in memory (analysis results, rate‑limit counters, metrics, the SAML replay cache, the OIDC discovery cache) — and your own `log_api` Docker image runs `uvicorn --workers 2`, with a Helm chart that scales replicas. Under that deployment, those features silently degrade or break.
2. **Scope has outrun depth in a few flagship areas.** The dashboard is heavily tested; the two services your CV actually showcases (`threat_api`, `log_api`) are barely tested. The "ML anomaly detection" and "dark‑web / social OSINT" features are weaker than their names imply.
3. **A handful of concrete security gaps** — none catastrophic, most subtle — that are worth fixing and worth being able to talk about.
4. **Repository‑hygiene and positioning issues** that cost you nothing to fix and disproportionately affect first impressions.

Severity legend used below: **🔴 High** (fix before showcasing/deploying) · **🟠 Medium** (fix soon; likely interview probe) · **🟡 Low** (polish / nitpick) · **🔵 Positioning** (affects how the work is *perceived*, not the code).

---

## 2. What is genuinely strong (don't lose this in the noise)

Be ready to say all of this out loud — it's the strongest part of your story.

- **Secrets & auth fundamentals.** `auth.py` uses PBKDF2‑HMAC‑SHA256 at 600k iterations with self‑describing cost markers (so cost can rise without invalidating old hashes), `hmac.compare_digest` for hash/secret comparison, and a session model with revocation epochs, per‑device sessions, and sliding idle‑timeout. `config.py` generates and persists a per‑install random JWT secret (no shared "dev‑insecure" default) and *fails fast* in production if real secrets aren't set.
- **RBAC done properly.** `permissions.py` enforces named capabilities (`siem.write`, etc.) rather than scattering role strings, custom roles are **fail‑closed**, and denials are audited.
- **SQL is parameterised.** Despite many `execute(f"…")` calls, every one I checked interpolates only *identifiers / placeholder counts / hardcoded column allowlists*; user **values** are always bound as `?`. No SQL injection found.
- **You avoided every classic footgun.** Zero `eval`/`exec`, `subprocess`/`shell=True`, `pickle`, `yaml.load`, `verify=False`, or `debug=True` anywhere in the Python.
- **SAML & OIDC show real expertise.** `saml.py` reads **only** from the element `signxml` reports as signed (the correct XML‑signature‑wrapping defence), pins the IdP cert instead of trusting embedded KeyInfo, and enforces issuer/audience/recipient/time‑window/InResponseTo with replay protection. `oidc.py` verifies RS256 against JWKS and **rejects `alg=none`/algorithm confusion**, and checks iss/aud/exp/nonce.
- **Supply chain & CI are mature.** Base images are **digest‑pinned**; Dependabot bumps them; CI runs all three pytest suites on push/PR, tests the dashboard against a **live Postgres** container, runs `pip-audit --strict`, gates `npm audit` with an *expiring* allowlist (triage can't rot silently), and runs Playwright e2e. `dashboard_api`'s Dockerfile runs **non‑root** with a healthcheck. This is better DevSecOps than many paid teams ship.
- **Documentation is thorough.** The 1,000‑line README documents architecture, the data pipeline, per‑role dashboard usage, multiple install paths, and deployment.

Keep this list. When an interviewer asks "what are you proud of," these are the answers.

---

## 3. Findings

### A. Architecture & scaling (cross‑cutting — the most important section)

**[A1] 🔴 Single‑process state under a multi‑worker deployment.**
*Where:* `log_api/main.py` (`_results: dict = {}`, `metrics`), `log_api/Dockerfile` (`uvicorn … --workers 2`), `threat_api/rate_limit.py` (`SimpleRateLimiter` in‑memory), `dashboard_api/saml.py` (`_seen` replay cache), `dashboard_api/oidc.py` (`_cache`), `deploy/helm` (replicas).
The code assumes one process; the deployment runs many. Concrete consequences:
- `POST /analyse` stores the result in worker A's `_results`; a follow‑up `GET /results/{id}` or `/report` routed to worker B returns **404 / the wrong report**. With `--workers 2` this happens ~half the time.
- `/metrics` and `/trends/severity` report only the serving worker's slice.
- The rate limiter allows roughly *N × limit* across N workers/replicas and resets on restart.
- The SAML one‑time‑use assertion cache and OIDC discovery cache are per‑worker (you acknowledge the SAML one in a comment).
**Fix:** move shared runtime state out of process memory. Pragmatic path given your stack: persist analysis results and metrics to SQLite/Postgres (you already persist *jobs*), back the rate limiter and SAML replay set with the DB (or Redis), and only then scale workers. Short‑term, if you must stay single‑process, set `--workers 1` and document it — but the durable fix is externalised state.

**[A2] 🟠 Analysis results are an unbounded in‑memory leak.**
*Where:* `log_api/main.py` `_results[job_id] = result`.
Every analysis result (with all findings) is kept in a module‑level dict **forever** — never evicted, never persisted. A long‑running instance grows until OOM, and all results vanish on restart even though the `analysis_jobs` row still says `completed` (so `job_status` adds a `result_url` only `if row[0] in _results`, i.e. inconsistently).
**Fix:** persist results to the DB (a `results` table or a JSON/STIX blob keyed by `job_id`), serve `/results/{id}` from there, and drop the in‑memory dict (or make it a bounded LRU as a cache only).

**[A3] 🟠 SQLite is the scaling ceiling for a "SIEM/SOAR platform."**
*Where:* all three `db.py` files; `dashboard_api/db_backend.py`.
SQLite WAL gives concurrent *reads* but still serialises *writes* to a single writer. For a product that ingests telemetry and runs background engine/scheduler/webhook threads alongside request handlers, write contention will produce `database is locked` beyond the 5s `busy_timeout` under real load. You clearly know this (the staged Postgres seam in `db_backend.py`), but that path is `# pragma: no cover` and relies on a **regex‑based SQL dialect translator** (`to_postgres`) — translating SQL with regexes is leaky and will bite on edge cases.
**Fix:** for the demo, SQLite is fine — just *say so* honestly (see [H2]). If you want the platform claim to hold, finish and test the Postgres backend against the full suite (your CI already spins up Postgres — extend coverage), and replace the regex translator with a proper query layer or parameter‑style abstraction.

**[A4] 🟡 New DB connection per call (no pooling).**
*Where:* `get_conn()` in each `db.py` opens and closes a connection on every use.
For SQLite this is cheap‑ish but wasteful under load and re‑runs PRAGMAs each time; for the Postgres path it's a real cost.
**Fix:** a thread‑local or pooled connection (e.g. a small connection pool, or `sqlite3` connection cached per thread) — minor for SQLite, important if Postgres becomes real.

---

### B. Security

**[B1] 🟠 SSRF guard is validate‑time only and bypassable via DNS rebinding / TOCTOU.**
*Where:* `dashboard_api/net_guard.py`; delivery in `dashboard_api/webhooks.py`.
`validate_external_url` resolves the host and range‑checks the IPs *when the URL is registered*, but `httpx` re‑resolves DNS *when the request is actually sent*. An attacker who controls a hostname can return a public IP at validation time and `169.254.169.254` (cloud metadata) or `127.0.0.1` at delivery time. The delivery functions (`_post_with_retry`, `deliver_slack`) don't re‑validate at send time at all. The "DNS failure ⇒ allow" rule also widens the gap.
**Fix:** resolve once and **pin the connection to the validated IP** (custom `httpx` transport / `resolver`, or pass the IP and set the `Host` header), block redirects on these clients, and re‑validate at delivery. At minimum, document that private‑range protection is best‑effort and require `DASHBOARD_ALLOW_PRIVATE_URLS` to be explicitly false in production.

**[B2] 🟠 Webhooks are global, not tenant‑scoped — cross‑tenant event leakage.**
*Where:* `dashboard_api/webhooks.py` `_subscribers()` (`SELECT … FROM webhooks WHERE status != 'paused'` with no org filter); docstring even says external webhooks are "global config."
You advertise multi‑tenancy (orgs, `org_id`, workspace scoping). But any user with `config.manage` can register a webhook that receives **every** tenant's events, because dispatch fans out to all webhooks globally. In a multi‑tenant deployment that's a confidentiality break.
**Fix:** add `org_id` to the `webhooks` table, scope `_subscribers()` by the event's org, and scope webhook CRUD to the caller's org. If multi‑tenancy is aspirational, say so and gate webhook management to a single‑tenant admin.

**[B3] 🟠 Frontend stores the JWT in `localStorage` and passes it in the SSE URL.**
*Where:* `frontend/lib/api.ts`, `frontend/lib/auth-context.tsx` (`localStorage.setItem(TOKEN_KEY, …)`), and `/stream?token=…`.
- `localStorage` is readable by any JavaScript, so **any XSS exfiltrates the session token** (httpOnly cookies can't be read by JS). For a *security* product this is a notable posture choice.
- Putting the long‑lived JWT in the SSE query string leaks it into server/proxy access logs, browser history, and Referer headers. (You correctly avoid this for SSO by using the URL fragment — apply the same care here.)
**Fix:** prefer an httpOnly, `Secure`, `SameSite` cookie for the session (with CSRF protection), *or* keep `localStorage` but add a strict CSP ([B4]) and mint a **short‑lived, single‑use stream ticket** for the SSE connection instead of the real JWT.

**[B4] 🟠 No Content‑Security‑Policy or HSTS on the frontend.**
*Where:* `frontend/nginx.conf` sets `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` (good) — but **no `Content-Security-Policy` and no `Strict-Transport-Security`.**
CSP is the highest‑leverage XSS mitigation, and it's exactly what would blunt the `localStorage` token‑theft risk in [B3].
**Fix:** add a locked‑down CSP (script‑src self + hashes/nonces, no `unsafe-inline` if achievable with Next.js), and HSTS with a sensible max‑age. Mirror the same headers in `vercel.json` if you deploy on Vercel.

**[B5] 🟠 `log_api` compares API keys non‑constant‑time and defaults CORS to `*` with credentials.**
*Where:* `log_api/main.py` (`api_key not in (USER_API_KEY, ADMIN_API_KEY)`, `api_key != ADMIN_API_KEY`); `log_api/config.py` (`CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")`) + `allow_credentials=True`.
This is inconsistent with your own better code: `threat_api` uses `hmac.compare_digest` and `dashboard_api` *refuses* a `*` origin when credentials are on. `log_api` does neither. (`threat_api` also defaults CORS to `*`.) Browsers reject `*`+credentials so it "fails safe" in practice, but it signals inconsistency an interviewer will notice, and the timing comparison is a (low‑risk) side channel.
**Fix:** use `hmac.compare_digest` for key checks in `log_api`; default `CORS_ORIGINS` to explicit localhost origins and reject `*` when credentials are enabled, exactly as `dashboard_api` does.

**[B6] 🟠 Error responses leak internal exception text.**
*Where:* `log_api/main.py` global handler returns `{"detail": str(exc)}`; `/analyse` raises `HTTPException(500, detail=str(e))`; `/ready` returns `{"error": str(e)}`.
Returning raw exception strings exposes internal paths, stack details, and dependency errors to callers (information disclosure).
**Fix:** log the exception server‑side with a correlation id; return a generic message + id to the client. Keep details out of HTTP bodies.

**[B7] 🟠 `threat_api` runs the Flask **development server** in its container, as root.**
*Where:* `threat_api/Dockerfile` (`CMD ["python","-m","threat_api.main"]` → `app.run(... debug=FLASK_DEBUG)`); no `USER` directive; no healthcheck. Same root issue in `log_api/Dockerfile`.
Flask's `app.run` (Werkzeug) is explicitly *not for production* — single‑process, not hardened. And only `dashboard_api` drops privileges; `threat_api` and `log_api` run as root, so a container escape/RCE starts as root.
**Fix:** serve `threat_api` with `gunicorn` (or `waitress`) behind the same pattern as the others; add a non‑root `USER` and a `HEALTHCHECK` to both `threat_api` and `log_api` Dockerfiles (copy the `dashboard_api` Dockerfile's hardening verbatim).

**[B8] 🟡 MFA: verify the route rate‑limits and reject OTP replay within the step window.**
*Where:* `dashboard_api/mfa.py` (`verify_code` accepts ±1 step) + the enrolment/verify route in `routers/auth.py`.
The TOTP/recovery‑code crypto is correct, but the module itself doesn't (a) prevent reuse of a still‑valid code within its 30s window, or (b) rate‑limit guesses. With ±1 window and 6 digits, online brute force is feasible without lockout. (You *do* have `AUTH_MAX_FAILURES`/throttling for password login — confirm it also covers MFA verify.)
**Fix:** track the last accepted TOTP counter per user and reject reuse; ensure MFA verification shares the failed‑attempt throttle and locks after N attempts.

**[B9] 🟡 SAML/OIDC residual gaps (you got the hard parts right; these are the edges).**
*Where:* `dashboard_api/saml.py`, `oidc.py`.
- SAML replay cache `_seen` is per‑worker (see [A1]); an assertion could be replayed against a different worker inside its validity window. *Fix:* shared replay store.
- An assertion **with no `AudienceRestriction`** is accepted (`if audiences and …`). *Fix:* require an audience and reject if absent for SP‑initiated flows.
- `make_authn_request` builds XML by string concatenation with a hand‑rolled escaper and sends an **unsigned** AuthnRequest. *Fix:* prefer a builder, and sign the request if your IdPs expect it.
- OIDC flow has **no PKCE**. For a confidential client it's not mandatory, but OAuth 2.1 expects it. *Fix:* add `code_challenge`/`code_verifier`.
- OIDC JWKS selection falls back to "first RSA key" when `kid` doesn't match. *Fix:* require a `kid` match.

**[B10] 🔵→🟡 Hand‑rolled crypto, and a justification that contradicts itself.**
*Where:* `auth.py` (custom HS256 JWT) vs `secretstore.py`/`oidc.py`/`saml.py` (which all import `cryptography`).
`auth.py` says it hand‑rolls JWT because "PyJWT… imports `cryptography`'s Rust bindings which are broken here" — but `secretstore.py` uses `cryptography.fernet` and `oidc.py` uses `cryptography` for RSA, *and `cryptography>=49` is a hard dependency*. So the stated reason is stale/false. The hand‑rolled HS256 is actually safe against alg‑confusion (it never branches on the header alg), so this isn't a live vuln — but rolling your own JWT, SAML, and SCIM is an **assurance and maintenance risk** (these areas have a long CVE history that vetted libraries have already absorbed), and the contradictory comment is exactly the kind of thing an interviewer catches.
**Fix:** reconcile the comment with reality; since `cryptography` works, prefer a maintained JWT library (PyJWT / Authlib / `joserfc`) and a maintained SAML library (`python3-saml`/`pysaml2`) for anything beyond a portfolio. If you keep the hand‑rolled versions, *delete the false justification* and replace it with an honest "I implemented these to demonstrate I understand the mechanics."

**[B11] 🟡 Per‑user Slack webhook + companion‑service calls also ride the SSRF path.**
*Where:* `webhooks.py` `deliver_slack`, `routers/services.py`/`platform.py` httpx calls.
Same root issue as [B1]: user‑supplied Slack URLs should pass `validate_external_url` at *send* time, and outbound calls to companion services should have explicit timeouts everywhere (most do; `services.py:180` and `platform.py:219` rely on httpx's 5s default rather than an explicit value).
**Fix:** set explicit timeouts on every outbound call and route user‑supplied URLs through the (hardened) SSRF guard at send time.

**[B12] 🟡 Long session lifetime, no refresh‑token rotation.**
*Where:* `config.py` `JWT_TTL_MINUTES = 720` (12h).
A 12‑hour bearer token in `localStorage` is a wide window if stolen. You have idle‑timeout and revocation epochs (good), but no short‑lived access + rotating refresh model.
**Fix:** consider shorter access tokens with refresh rotation, or at least document the 12h choice and pair it with the idle timeout.

---

### C. Detection & CTI efficacy (your flagship features — where interviewers will dig)

**[C1] 🟠 The ML detector flags ~5% of entities as "anomalies" *by construction*, even on benign logs.**
*Where:* `log_api/detectors/ml_detector.py`.
You fit an `IsolationForest` with a fixed `contamination=0.05` **on the same single file you're scoring** — there's no persisted baseline of "normal." `contamination` is the assumed outlier fraction, so the model will label roughly 5% of IPs as anomalous *regardless of whether anything is actually wrong*. On a completely clean log it still emits "anomalies." Severity is then min‑max‑normalised *within that one file*, so the same behaviour scores differently depending on the other rows.
**Fix:** train on a known‑good baseline and persist the model (score new data against it), or switch from `contamination` to a score *threshold* and present the output as a **ranking** ("most unusual sources") rather than a detection verdict. Be explicit in the UI/docs that this is unsupervised outlier ranking, not ground‑truth detection.

**[C2] 🟠 Every ML finding is hardcoded to MITRE ATT&CK `T1595` ("Active Scanning").**
*Where:* `ml_detector.py` `mitre_tags=[MitreTag(technique_id="T1595", …)]`.
A behavioural outlier driven by auth failures or off‑hours POST volume is *not* "Active Scanning." Mislabelling every ML hit with one technique is inaccurate ATT&CK mapping — and ATT&CK fluency is exactly what a SOC interviewer checks.
**Fix:** map technique from the dominant feature(s) (e.g. high `auth_fail` → T1110 Brute Force; many unique paths/high rate → T1595/T1046; off‑hours exfil‑shaped bytes → T1041), or omit the tag when you can't justify it.

**[C3] 🟠 "Dark‑web OSINT" and "social OSINT" are RSS wrappers, and empty by default.**
*Where:* `threat_api/fetchers/darkweb_osint.py`, `social_osint.py` (both call `rss._fetch_feed`/`_read_sources`); `darkweb_sources.txt` and `social_sources.txt` each contain **0** non‑comment lines; `rss_feeds.txt` has 4.
Both "sources" just read whatever URLs you list in a text file via the RSS fetcher and relabel results with `leak-mention` / `community-sourced` tags + a confidence bump. There's no Tor/onion collection and no social‑media API. And because the two source files are empty out of the box, the live pipeline effectively pulls only OTX + abuse.ch + 4 RSS feeds — so two of the "five OSINT sources" you cite contribute nothing by default. An interviewer who opens these files will see it immediately.
**Fix (pick one):** (a) rename to reflect reality ("curated leak/abuse RSS feeds," "community RSS feeds") and seed the files with a few real feeds; or (b) actually implement distinct collection (e.g. a paste/leak monitor, a Mastodon/Telegram public‑channel reader) so the names are earned. Either way, describe them honestly on the CV (see [H1]).

**[C4] 🟡 Whole‑file‑into‑memory parsing + per‑line regex on attacker‑controlled input.**
*Where:* `log_api/main.py` (`content = await file.read()` then `splitlines()`); the 2,000,000‑line cap is checked *after* the full read/decode/split.
A multi‑GB upload (or a single enormous line with no newlines) is fully buffered before the line check, enabling memory exhaustion. The parser regexes are mostly bounded (low ReDoS risk), but they run on each untrusted line.
**Fix:** enforce a byte‑size limit at ingress (reject by `Content-Length` / stream and stop early), cap per‑line length before regex, and consider streaming the file rather than `read()`‑ing it whole.

**[C5] 🟡 The HTML report has one latent XSS sink and a hand‑rolled escaper.**
*Where:* `log_api/reporter/report.py`.
You *do* escape the log‑derived fields (IP, username, evidence, description, etc.) — good, you clearly thought about log‑injection XSS. But the MITRE block interpolates `t.url` and the technique name **unescaped** into `href='…'` and link text. Those are server‑constant today (so not exploitable now), but it's a latent sink, and the hand‑rolled `_esc` doesn't escape single quotes.
**Fix:** render the report with an autoescaping templating engine (Jinja2 + MarkupSafe) instead of f‑strings, and escape *every* interpolated value including MITRE fields. Also see [C6] — the report file is shared.

**[C6] 🟠 One global report file shared across all users/analyses.**
*Where:* `log_api/main.py` `/report` serves `REPORT_OUTPUT_PATH` (default `anomaly_report.html`); `_run_analysis` overwrites it every run.
Concurrent analyses race on the same file, and `GET /report` returns whatever the *last* analysis wrote — so user A can fetch a report generated from user B's logs. Combined with [A1]'s worker split, behaviour is non‑deterministic.
**Fix:** generate per‑job report content (keyed by `job_id`, ideally rendered on demand from the stored result), and serve `/results/{id}/report`.

---

### D. Testing & quality assurance

**[D1] 🟠 The two services your CV showcases are essentially untested.**
*Where:* `dashboard_api/tests/` has **25** test files (incl. a 3,761‑line `test_api.py`, plus SAML/SCIM/SSO/RBAC/sessions/MFA‑recovery/webhook‑signing/net_guard/password‑policy/privacy/retention suites). `threat_api/tests/` and `log_api/tests/` each contain **only `test_health.py`.**
So the parsers, the four detectors, trust‑scoring, IOC normalisation, the STIX converter, and the fetchers — the exact "ThreatOrbit" pipeline your CV leads with — have **no unit tests**. That's the inverse of where your CV points, and it's the first thing a reviewer notices when they open `tests/`.
**Fix (highest‑leverage single action):** add focused unit tests to `threat_api` and `log_api`:
- parsers: golden‑input → expected `ParsedLogEntry` for each format, plus malformed lines;
- detectors: synthetic logs with a *known* brute‑force / rate‑spike / off‑hours pattern → assert the right finding + severity + MITRE technique (this test will also force you to fix [C1]/[C2]);
- trust‑scoring & normalisation: table‑driven cases;
- STIX converter: validate output against the STIX 2.1 schema.
Even 20–30 of these transforms the credibility of the flagship code and gives you concrete interview material ("here's how I test detection logic").

**[D2] 🟡 `pip-audit` only covers `dashboard_api` dependencies.**
*Where:* `.github/workflows/security.yml` audits `dashboard_api/requirements.txt` only.
`threat_api` and `log_api` dependencies (Flask, requests, scikit‑learn, numpy, stix2, etc.) aren't CVE‑audited in CI.
**Fix:** run `pip-audit` on all three requirements files.

**[D3] 🟡 No Python lockfile (non‑reproducible builds).**
*Where:* all `requirements.txt` use `>=x,<y` ranges; the frontend has `package-lock.json` but Python has no `pip-compile`/hashes lock.
You have an SBOM script and supply‑chain workflow, so this is the missing piece for reproducibility/integrity on the Python side.
**Fix:** add a hash‑pinned lock (`pip-compile --generate-hashes`) per service.

---

### E. Containers, deployment & ops

**[E1] 🟠 Privilege & server inconsistency across the three Dockerfiles.**
*Where:* `dashboard_api/Dockerfile` is hardened (non‑root uid 10001, healthcheck, uvicorn); `threat_api` and `log_api` run **as root**; `threat_api` uses the Flask dev server (see [B7]); neither `threat_api` nor `log_api` has a `HEALTHCHECK`.
**Fix:** standardise all three on the `dashboard_api` pattern — non‑root user, healthcheck, production server.

**[E2] 🟡 Port defaults collide / drift from docs.**
*Where:* `threat_api/config.py` and `log_api/config.py` both default `API_PORT=8000`, while the README/compose put `log_api` on `8001`. Works because compose/Dockerfile override, but it's confusing.
**Fix:** make each service's default port match its documented port.

**[E3] 🟡 `ADMIN_API_KEY` falls back to the user key everywhere.**
*Where:* all three `config.py` (`ADMIN_API_KEY = os.getenv("ADMIN_API_KEY") or APP_API_KEY`).
In any single‑key setup the "two‑tier" scheme is cosmetic — user and admin are identical. It's documented, but it means the admin/user split many of your endpoints rely on doesn't exist unless both env vars are set.
**Fix:** in production (`REQUIRE_SECRETS`/equivalent), require a *distinct* admin key, or log a loud warning when they're equal.

**[E4] 🔵 Public demo exposure.**
*Where:* live demo at `threat-orbit-v2.vercel.app`; `config.py` seeds a default admin (`admin@threatorbit.space` / `ChangeMe123!`) and defaults `DATA_MODE=demo` with `REQUIRE_SECRETS` off.
If any backend is reachable in demo mode without `REQUIRE_SECRETS=true` and a changed admin password, the default admin is a real exposure.
**Fix:** ensure the public demo is frontend‑only *or* runs with `DASHBOARD_REQUIRE_SECRETS=true`, a changed admin password, and registration disabled.

---

### F. Repository hygiene & professionalism (cheap fixes, big first‑impression payoff)

**[F1] 🟠 42 compiled `.pyc` files are committed.**
*Where:* `log_api/**/__pycache__/*.pyc`, `threat_api/**/__pycache__/*.pyc` are tracked, even though `.gitignore` lists `__pycache__/` and `*.pyc` (they were committed before the ignore rules, so Git still tracks them).
This clutters the repo, pollutes diffs, and skews the language statistics.
**Fix:** `git rm -r --cached **/__pycache__` and commit; the ignore rules then keep them out.

**[F2] 🟠 No `LICENSE` file.**
Without a licence, the default is "all rights reserved" — nobody can legally reuse it, and reviewers read its absence as unfinished.
**Fix:** add a `LICENSE` (MIT or Apache‑2.0 are typical for a portfolio).

**[F3] 🟡 GitHub language bar shows ~83% TypeScript / ~16% Python.**
*Where:* `.gitattributes` only fixes `.bat` line endings; the committed `.pyc` files ([F1]) and the large Next.js frontend inflate non‑Python lines.
Your CV sells this as a "Python platform," but a recruiter glancing at the repo sees "TypeScript." (This is the same point from our earlier chat — still unaddressed.)
**Fix:** mark `frontend/` as `linguist-vendored` (or `linguist-documentation`) in `.gitattributes`, remove the committed `.pyc`, and consider splitting the frontend into its own repo. You want Python to read as the primary language.

**[F4] 🟡 `plan.md` (internal roadmap) is committed to `main`, and references a `CHANGELOG` that doesn't exist.**
*Where:* `plan.md` opens with "Roadmap to … feature parity with Splunk/Elastic … and past them" and a checklist workflow that says "move to CHANGELOG section"; there is **no `CHANGELOG` file**.
The roadmap is fine to keep, but the "parity with Splunk/Elastic and beyond" framing on `main` invites the over‑claiming critique in [H2], and the dangling CHANGELOG reference looks unfinished.
**Fix:** either move `plan.md` to a `docs/` or a branch, tone down the comparative claims, and add a real `CHANGELOG.md` (or remove the references).

---

### G. Maintainability & structure

**[G1] 🟠 Scope is very large for one maintainer.**
Three backends + a full dashboard SPA + SSO (OIDC/SAML/SCIM) + billing + SOAR + multi‑tenancy + Helm is a *lot* of attack surface and maintenance for a solo project — each enterprise feature (especially the SSO/SCIM/billing trio) is a security‑sensitive area that needs ongoing care. Breadth is impressive but dilutes depth (see the testing imbalance in [D1] and the half‑built Postgres path in [A3]).
**Fix:** for the portfolio, consider designating a *core* you can defend deeply (the CTI + log‑analysis pipeline) and explicitly marking the enterprise features as "exploratory / not production‑audited." Depth on the core beats breadth you can't fully stand behind in an interview.

**[G2] 🟡 Duplication across services.**
`config.py`, `db.py`, API‑key auth, rate limiting, and metrics are re‑implemented (and subtly diverge — e.g. constant‑time compare in `threat_api` but not `log_api`; `*`‑CORS guarded in `dashboard_api` but not the others). Divergence is how inconsistencies like [B5] arise.
**Fix:** factor shared concerns into a small common package (or at least keep the three implementations in lockstep with a checklist).

**[G3] 🟡 SQL safety depends on developer discipline (no ORM).**
The f‑string‑with‑allowlist pattern is correct *today*, but it's one careless edit away from injection because there's no structural guard.
**Fix:** either adopt a light query builder / ORM for the mutable paths, or add a lint/test that asserts no user‑derived value reaches an f‑string SQL position.

---

### H. Documentation & positioning (this is the part that affects your job hunt most directly)

**[H1] 🔵 Align the CV with what the code actually does.**
Two CV lines are currently over‑stated relative to the repo:
- *"five OSINT sources (AlienVault OTX, abuse.ch, RSS, dark‑web, social)"* — dark‑web and social are RSS wrappers and empty by default ([C3]). Reframe as: *"extensible OSINT ingestion (OTX, abuse.ch, and a pluggable RSS layer with slots for leak/abuse and community feeds)."*
- *"machine‑learning (Isolation Forest) … severity‑rated anomalies"* — true, but it's unsupervised outlier *ranking* with a fixed contamination, not trained detection ([C1]). Reframe as: *"an unsupervised Isolation‑Forest layer that ranks the most unusual sources for analyst triage."*
Honest, precise framing is *more* impressive than inflated framing, and it removes the landmines an interviewer would otherwise step on.

**[H2] 🔵 Calibrate the "platform" / "parity with Splunk" narrative.**
The README + `plan.md` lean hard on enterprise‑platform framing, while the substance is a single‑node SQLite app with an in‑memory result store and untested core detectors. Reviewers who notice the gap may discount the *whole* project — including the genuinely strong parts. The cure isn't to hide the ambition; it's to add an honest **"Status & limitations"** section: "single‑node SQLite (Postgres path staged); detector layer is heuristic + unsupervised ranking; SSO/SCIM/billing are exploratory and not production‑audited." That one section converts "is this vaporware?" into "this person has excellent judgement about their own work."

**[H3] 🟡 Add visuals + a "skills demonstrated" map to the README.**
A screenshot/GIF of a log‑analysis run and the dashboard, plus a short table mapping features → SOC competencies (triage, IOC enrichment, detection logic, CTI lifecycle, ATT&CK mapping), makes the value legible in 10 seconds to a non‑reader recruiter.

---

## 4. Prioritised remediation checklist

**P0 — do before you point anyone (recruiter/interviewer) at the repo:**
- [ ] [F1] Remove committed `.pyc`; [F2] add `LICENSE`; [F3] fix the language bar (`.gitattributes`).
- [ ] [D1] Add unit tests to `threat_api` + `log_api` (parsers, detectors, trust‑scoring, STIX). *Single highest‑value action.*
- [ ] [H1]/[H2] Re‑word the two over‑stated CV lines and add a "Status & limitations" section.
- [ ] [C1]/[C2] Fix the ML detector's by‑construction false positives and the hardcoded T1595 (a test from [D1] will force this).
- [ ] [E4] Confirm the public demo isn't exposing the default admin.

**P1 — fix soon (likely interview probes / real risk):**
- [ ] [A1]/[A2] Externalise `log_api` results + rate‑limit/SAML/OIDC state, *or* run single‑worker and document it.
- [ ] [B2] Scope webhooks per‑tenant; [B6] stop leaking exception text; [B5] constant‑time keys + CORS fix in `log_api`.
- [ ] [B7]/[E1] Non‑root + production server + healthcheck for `threat_api`/`log_api`.
- [ ] [C3] Make dark‑web/social honest (rename or implement); [C6] per‑job reports.
- [ ] [B4] Add CSP + HSTS; [B3] move the token off `localStorage`/out of the SSE URL.
- [ ] [B10] Reconcile the false "cryptography is broken" comment.

**P2 — polish / depth:**
- [ ] [A3] Finish + test the Postgres path or commit to SQLite‑with‑limits; [A4] pool connections.
- [ ] [B1]/[B11] Harden SSRF (pin resolved IP, re‑validate at send, explicit timeouts).
- [ ] [B8]/[B9]/[B12] MFA replay + rate‑limit; SAML audience/replay/signed request; OIDC PKCE; session TTL.
- [ ] [D2]/[D3] Audit all deps in CI; add a Python lockfile.
- [ ] [F4] Tidy `plan.md`/add `CHANGELOG`; [G1]/[G2]/[G3] scope/dedup/SQL‑safety.
- [ ] [H3] README visuals + skills map.

---

## 5. Turn every finding into an interview strength

Interviewers don't expect a portfolio to be flawless — they're testing whether you can **see** the flaws and reason about trade‑offs. Pre‑load these answers:

- *"How would you scale this past one box?"* → "Today it's single‑node SQLite with some in‑memory state ([A1]/[A3]); I'd externalise the result store and rate‑limiter to the DB/Redis and finish the Postgres backend — my CI already runs the suite against Postgres."
- *"Is your ML actually detecting attacks?"* → "It's unsupervised outlier *ranking* with a fixed contamination, so on clean data it still surfaces ~5% — I treat it as triage assistance, and the honest next step is a persisted known‑good baseline ([C1])."
- *"Walk me through your SSO."* → Lead with the XSW defence and cert pinning (genuinely strong), then volunteer the gaps yourself (per‑worker replay cache, no PKCE) and say you'd delegate to `pysaml2`/Authlib for production ([B9]/[B10]). Volunteering the weakness is what scores points.
- *"What's your SSRF story?"* → "App‑level allow‑list today; I know it's bypassable via DNS rebinding, so the real fix is pinning the resolved IP at connect time ([B1])." That single sentence signals senior‑level awareness.
- *"What would you fix first?"* → point at this checklist. Having a prioritised, self‑authored remediation plan is itself a strong signal.

The fact that the hard parts (auth, RBAC, signature verification, CI/supply‑chain) are *right* is what makes the gaps forgivable. Fix the P0 list, learn to narrate the rest, and this project becomes a genuine asset rather than a liability in your SOC‑analyst search.

---

## 6. Re-verification & remediation log (2026-06-21)

This report was written a few revisions back. On 2026-06-21 every finding above
was re-checked against the current `main`, and a new responsive / cross-device
finding (raised after viewing the landing page on a wide monitor and a
touchscreen) was added and fixed. Items marked **OPEN** below are being worked
through in the same remediation pass (follow-up commits); this log is updated as
each lands.

Status key: **FIXED** (resolved in code) · **PARTIAL** (materially improved,
residue noted) · **OPEN** (still present, being addressed) · **INFRA**
(deployment-time / outside the code).

### New findings (this round)

**[I1] Wide screens left large empty gutters; content was a fixed width. — FIXED**
*Where:* every marketing/site section and the docs shell used a hardcoded
`max-w-7xl` (80rem) container, so on 1920px / 2560px / ultrawide displays the
content stayed ~1280px wide and centred, wasting hundreds of pixels of dead space
on each side.
*Fix:* introduced one fluid `.site-container` class (`frontend/app/globals.css`)
whose width tracks the viewport — `max-width: clamp(80rem, 88vw, 130rem)` with
viewport-scaled side padding — and replaced all 18 `max-w-7xl mx-auto px-6`
usages with it (Hero, Features, Pricing, About, StatsBar, Footer, Navbar,
MegaMenu, the docs shell, etc.). Laptops are visually unchanged (still ~80rem);
desktop and ultrawide now use the available width so the empty gutters are gone,
capped at a readable 130rem. One class = one source of truth, so new sections
flex automatically.

**[I2] Hover-to-reveal sidebars misbehaved on touchscreens. — FIXED**
*Where:* the dashboard `Sidebar` expanded on `onMouseEnter`/`onMouseLeave`, and the
landing `LandingSidebar` opened from a 4px `onMouseEnter` strip. Touch devices have
no real hover — a tap fires a sticky synthetic `mouseenter` with no matching
`mouseleave` — so the rail opened half-way or stuck open ("not smooth").
*Fix:* added a shared `useCoarsePointer()` hook (`frontend/lib/usePointer.ts`,
backed by `(pointer: coarse)`). On coarse pointers the dashboard rail no longer
hover-expands; the collapsed rail becomes an explicit tap-to-expand target and
collapses again on navigation (drawer-like), while mouse/trackpad users keep the
smooth hover. The landing hover strip renders only for hover-capable pointers
(touch users already have the always-visible Navbar menu / MegaMenu). A
touch-laptop with a trackpad reports `pointer: fine`, so it correctly keeps hover.
Guiding principle applied: design for any device/environment from the start.

### Status of the original findings (re-verified 2026-06-21)

| ID  | Title (short)                              | Status |
|-----|--------------------------------------------|--------|
| A1  | Single-process state vs multi-worker       | PARTIAL — log_api results persisted + `--workers 1`; threat_api rate-limiter in-proc (fine single-process) |
| A2  | Unbounded in-memory result leak            | FIXED — persisted to SQLite |
| A3  | SQLite scaling ceiling                      | INFRA — Postgres seam staged |
| A4  | New DB connection per call (no pooling)     | OPEN |
| B1  | SSRF validate-time only / rebinding         | OPEN |
| B2  | Webhooks not tenant-scoped                  | FIXED — `org_id` + scoped `_subscribers()` |
| B3  | JWT in localStorage + token in SSE URL      | OPEN — SSE-URL leak being fixed |
| B4  | No CSP / HSTS                               | PARTIAL — set in frontend nginx + vercel.json; root vercel.json CSP being added |
| B5  | log_api non-constant-time keys + CORS `*`   | FIXED |
| B6  | Error responses leak exception text         | FIXED |
| B7  | threat_api Flask dev server as root         | FIXED — gunicorn, non-root, healthcheck |
| B8  | MFA replay / rate-limit                     | PARTIAL — login path tracks TOTP counter; step-up being hardened |
| B9  | SAML/OIDC residual gaps                      | PARTIAL — OIDC kid pinned; SAML audience + OIDC PKCE being added |
| B10 | Hand-rolled crypto justification            | FIXED — comment corrected |
| B11 | Slack/companion SSRF + explicit timeouts    | FIXED — explicit timeouts everywhere |
| B12 | 12h session, no refresh rotation            | INFRA — configurable TTL; documented |
| C1  | ML flags ~5% by construction                | FIXED — `contamination='auto'` + corroboration |
| C2  | Every ML finding tagged T1595               | FIXED — technique derived from dominant signal |
| C3  | Dark-web/social OSINT empty wrappers         | OPEN — seeding + honest naming |
| C4  | Whole-file-into-memory parse                | FIXED — byte cap at ingress |
| C5  | Report XSS sink + weak escaper              | FIXED — all fields escaped incl. quotes |
| C6  | One shared report file                      | FIXED — per-job reports |
| D1  | threat_api/log_api untested                 | OPEN — adding unit tests |
| D2  | pip-audit only dashboard_api                | FIXED — all three audited |
| D3  | No Python lockfile                          | OPEN |
| E1  | Dockerfile hardening inconsistency          | FIXED |
| E2  | Port defaults drift                         | PARTIAL — container ports correct; documented |
| E3  | ADMIN_API_KEY falls back to user key        | FIXED — warns loudly when unset |
| E4  | Public demo exposure                        | INFRA — deployment-time |
| F1  | Committed `.pyc`                            | FIXED — none tracked |
| F2  | No LICENSE                                  | FIXED — MIT added |
| F3  | Language bar TS-heavy                       | OPEN — `.gitattributes` |
| F4  | plan.md references missing CHANGELOG        | OPEN — adding CHANGELOG.md |
| G1-3| Scope / duplication / SQL discipline       | INFRA / ongoing |
| H1-3| CV / README positioning                    | OPEN — README "Status & limitations" + skills map |
| I1  | Wide-screen fixed width / empty gutters     | FIXED (this round) |
| I2  | Hover sidebars on touch                     | FIXED (this round) |
