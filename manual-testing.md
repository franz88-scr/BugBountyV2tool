# Manual Testing Guide — Beyond the Pipeline

The automated pipeline (phases A–L) covers recon plus the following **new automated phases**
that address previously manual gaps:

| Phase | What It Automates | Artifact |
|-------|------------------|----------|
| `G2`  | SSTI fuzzing on param-bearing URLs | `ssti.txt` |
| `J`   | Origin IP bypass (favicon hash, crt.sh, MX records, resolved-IP ASN check) | `origin.txt` |
| `K`   | Deep JS secrets (custom regex for 13 secret types, source map extraction) | `js_secrets_deep.txt` |
| `L`   | Auth bypass header fuzzing, mass-assignment field listing, API endpoint collection | `auth_bypass.txt` |

Run them: `reconchain.py -d example.com -o ./out --only G2,J,K,L`

However, several critical attack surfaces are **only addressable manually**. This guide
catalogues common gaps with actionable steps.

## J1 — API Endpoint Probing (IDOR / Auth Bypass / Mass Assignment)

> **🔄 Phase L now automates** auth bypass header fuzzing and endpoint collection (`auth_bypass.txt`).
> The manual steps below cover **IDOR** and **authenticated mass assignment** — things that need
> two user sessions and domain knowledge.

Common endpoints to test:

| Endpoint | Likely Methods | Test For |
|----------|---------------|----------|
| `/api` | GET, POST | IDOR on object references, mass assignment on POST bodies |
| `/account` | GET, POST, PUT | Privilege escalation by modifying `role`/`admin` fields |
| `/login` | POST | Auth bypass via parameter pollution, SQLi, NoSQLi |
| `/register` | POST | Mass assignment during user creation (e.g. `is_admin=true`) |
| `/password` | GET, POST | Reset-token leakage, weak HMAC, enumeration |
| `/user` | GET, PUT, DELETE | IDOR on `user_id`, unauthorised access to other users' data |

**Action items:**
- [ ] Probe each endpoint with a **low-privilege session cookie** and attempt to
  access/modify resources belonging to other users (IDOR).
- [ ] For POST/PUT endpoints, send extra JSON fields like `role`, `admin`, `is_admin`,
  `permissions`, `balance` to test for mass assignment.
- [ ] Try auth bypass techniques: `X-Original-URL`, `X-Rewrite-URL`, path traversal
  (`/../admin`), HTTP method override (`X-HTTP-Method-Override: PUT`).

## J2 — JS Secrets Review

> **🔄 Phase K now automates** deep JS secret scanning with 13 custom regex patterns (Firebase,
> Stripe, GitHub tokens, AWS keys, JWTs, internal IPs/hosts, GraphQL endpoints) plus source map
> extraction (`js_secrets_deep.txt`). Run with `--only K` before manual review.

The automated SecretFinder misses many patterns (e.g. obfuscated keys, Firebase URLs,
internal GraphQL endpoints). Secrets discovered by the pipeline should be manually reviewed.

```bash
# Extract high-entropy strings from JS files
cd out
cat urls_js.txt | while read u; do
  curl -s "$u" | entropy-threshold -m 4.5 -l 20 >> j2_high_entropy.txt
done
```

**Action items:**
- [ ] Manually audit each secret in `js_secrets.txt` — prioritise API keys,
  Firebase/Cloud URLs, JWTs, and internal hostnames.
- [ ] Run custom regex scans for: `AIza[0-9A-Za-z\-_]{35}` (Firebase),
  `sk_live_`/`pk_live_` (Stripe), `ghp_` (GitHub tokens).
- [ ] Check for exposed internal endpoints in JS source maps (`.map` files).
- [ ] Re-run on every deploy — JS secrets rotate frequently.

## J3 — Deep Parameter Discovery

Automated tools (Arjun/x8) can be shallow. Many apps have more parameters than discovered.

```bash
# Arjun with tighter settings
arjun -i urls_all.txt -t 20 -o json/params_deep.json --headers "Cookie: <session>"

# x8 with max depth
x8 -u urls_all.txt -o json/params_x8_deep.json \
  --max-params 10 --max-values 5 --max-param-name-length 64

# ParamSpider per endpoint with high level
paramspider -d "$(echo $URL | sed 's|https\?://||;s|/.*||')" --level high --quiet
```

**Action items:**
- [ ] Enumerate parameters with an **authenticated session** (logged-in endpoints often
  expose more params than anonymous ones).
- [ ] Review web traffic passively for parameters not collected by tools (e.g. from
  websockets, GraphQL queries in JS).
- [ ] Test common hidden params: `debug`, `admin`, `source`, `test`, `env`, `token`.

## J4 — Cloudflare Origin Bypass

> **🔄 Phase J now automates** origin IP discovery via favicon hash (Shodan-compatible), crt.sh
> certificate history, MX record extraction, and resolved-IP collection (`origin.txt`).
> Run with `--only J`.

If the target uses Cloudflare, the real server IP may be obscured. Several techniques
can reveal it:

```bash
# Historical DNS (SecurityTrails API)
curl -s "https://api.securitytrails.com/v1/domain/$DOMAIN/history?apikey=$ST_APIKEY"

# Censys / Shodan — search for SSL cert subject/organisation
censys search "$DOMAIN" --index certificates
shodan search "ssl.cert.subject.cn:$DOMAIN"

# DNS brute-force with full-zone-transfer attempt
dig axfr @ns-cloud-e1.googledomains.com $DOMAIN

# Check subdomains pointing to non-Cloudflare IPs
# Review resolved_full.txt — any IP that doesn't belong to Cloudflare ASN (13335)
# is a candidate origin.

# SMTP / MX records — sometimes MX servers are not proxied
dig mx $DOMAIN
```

**Action items:**
- [ ] Check Censys, Shodan, and SecurityTrails for historical A records.
- [ ] Review `resolved_full.txt` — any hostname that resolves to a non-CF IP may be the origin.
- [ ] Try Favicon hash lookup (`mmh3` hash of `/favicon.ico` on Shodan).
- [ ] Once an origin IP is found, re-run phases C1–G targeting it directly.

## J5 — Business Logic Testing

Business logic flaws **cannot be detected by automated scanners**. Common attack surfaces
in web applications include:

| Feature | Potential Flaw | How to Test |
|---------|---------------|-------------|
| Grade/task submission | Grade manipulation | Intercept POST to relevant API; modify `score`/`points`/`completed` |
| User collaboration | Accessing other users' data | Change `user_id`, `student_id`, or `assignment_id` in API calls |
| Group/role membership | Privilege escalation | Try adding yourself to a privileged group via membership endpoints |
| Deadlines / due dates | Bypass restrictions | Submit after deadline; modify `due_date` param |
| File uploads (if any) | Arbitrary file upload | Upload `.php`/`.jsp`/`.war` files, check for path traversal in filename |
| Ratings / reviews (if any) | Rating manipulation | Submit multiple ratings, negative scores, or out-of-range values |

**Approach:**
1. Create **two accounts** with different privilege levels.
2. Map every state-changing request (POST/PUT/PATCH/DELETE).
3. For each request, swap identifiers between accounts via Burp Repeater.
4. Look for responses that leak another user's data or mutate another user's state.

## J6 — Active Vulnerability Fuzzing

> **🔄 Phase G2 now automates** SSTI fuzzing across all param-bearing URLs (`ssti.txt`).
> Phase G runs dalfox (XSS) and sqlmap (SQLi). These automated phases cover the easy
> payloads; the manual steps below cover edge cases and chained exploits.

```bash
# XSS — reflect/dom-based
cat urls_all.txt | while read u; do
  echo "$u?q=<script>alert(1)</script>" >> j6_xss_payloads.txt
done
# Run via XSS scanner
dalfox file urls_all.txt --custom-payload j6_xss_payloads.txt -o j6_xss.txt

# SQLi — time-based + error-based
sqlmap -m urls_all.txt --batch --level 3 --risk 2 --random-agent -o j6_sqli.txt

# SSTI — common template engines
cat urls_all.txt | while read u; do
  echo "$u?name={{7*7}}"
  echo "$u?name=\${7*7}"
done > j6_ssti_payloads.txt
# (then fuzz manually or with a custom script)

# Open redirect
cat urls_all.txt | while read u; do
  echo "$u?next=https://evil.com"
  echo "$u?redirect=https://evil.com"
done > j6_open_redirects.txt
# Check responses for Location headers
```

**Action items:**
- [ ] XSS: test reflected params, DOM sinks in JS files, and stored inputs (profile fields,
  assignment names, comments).
- [ ] SQLi: focus on discovered `/api` endpoints and `id`/`user_id` params.
- [ ] SSTI: look for params reflected in rendered output.
- [ ] SSRF: test `url`, `image`, `file`, `path` params; use the active interactsh domain from
  the pipeline's OAST phase.
