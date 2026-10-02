# AI-Assisted Subdomain Takeover Exposure Detector for a Property Management Test Environment

A defensive detection tool for **subdomain takeover exposure**, with an
LLM-assisted (Google Gemini) interpretation layer for ambiguous findings.
Tested exclusively against a local, self-authored lab environment - see
[`AUTHORIZATION_NOTE.md`](AUTHORIZATION_NOTE.md).

## What is subdomain takeover?

A subdomain takeover happens when a DNS record (usually a `CNAME`) still
points to a third-party service (GitHub Pages, an S3 bucket, a Heroku app,
an Azure App Service, etc.) that has since been deleted or was never
claimed. Anyone who registers that resource name on the provider can then
serve their own content under the victim's subdomain.

- **Root cause:** dangling DNS records left behind after decommissioning a
  service, without removing the DNS entry that pointed to it.
- **Impact:** phishing pages served under a trusted domain, cookie-scope
  abuse (if the parent domain's cookies are readable), CSP/CORS bypass via
  a "trusted" origin, and OAuth/email-verification abuse (an attacker
  controlling `mail.example.com` could intercept verification emails routed
  through it).
- **Detection (this tool):** follow the CNAME chain -> match it against a
  list of known claimable providers -> check whether the final target is
  dangling (NXDOMAIN) or resolves but serves an "unclaimed resource" error
  page with the right HTTP status.
- **Fix:** delete the dangling DNS record as soon as the underlying
  resource is decommissioned; or claim the resource before restoring the
  record. Maintain a DNS/asset inventory and a decommissioning checklist so
  records are removed at the same time as the resource, not afterwards.

## Project structure

```
lab_config.py            Lab configuration: domain, DNS/HTTP ports,
                          subdomain scenarios, ground-truth verdicts,
                          per-subdomain sensitivity/cookie-scope context
lab_dns_server.py         Local DNS server for the fake pms-lab.test zone
lab_http_server.py        Local HTTP server, virtual-hosts by Host header
fingerprints.json         Provider "unclaimed resource" fingerprints,
                          modelled on the community can-i-take-over-xyz list
targets.txt               Scan targets (5 lab hosts + example.com, out of
                          scope, to demonstrate the authorization guard)
subtakeover_scanner.py    The detector itself (DNS + HTTP + fingerprint
                          matching); writes scan_results.json
ai_interpreter.py         LLM-assisted (Gemini) interpretation layer;
                          reads scan_results.json, writes scan_results_ai.json
report_generator.py       Severity scoring + Markdown/JSON report generator
scan_results.json          Latest raw scanner output
scan_results_ai.json       Latest scanner output + AI/template interpretation
vulnerability_report.md/json  Final report (Detected Y/N | Evidence |
                          Severity | Remediation)
scan_results_baseline.json,
scan_results_ai_baseline.json  v1.0-baseline run, kept for before/after
                          comparison (see "Stage 5/6" below)
LIMITATIONS.md             Known limitations, honestly documented
AUTHORIZATION_NOTE.md      Confirms only the local lab was ever scanned
.gitignore
```

## Setup

- Python 3.12.6, `pip`, `git` (no Docker needed).
- Install dependencies:
  ```powershell
  pip install dnspython dnslib requests
  ```
- Get a free Google Gemini API key from https://aistudio.google.com/apikey
  (optional - the tool works without it, using offline template
  explanations instead of live AI interpretation).
- Set it **once**, permanently, as a Windows user environment variable so
  you never have to re-enter it per session:
  ```powershell
  setx GEMINI_API_KEY "your-real-key-here"
  ```
  Open a **new** PowerShell window afterwards for it to take effect.

## How to run (full pipeline)

```powershell
# 1. Run the scanner against the local lab and check it against ground truth
python subtakeover_scanner.py --start-lab --evaluate

# 2. Add LLM-assisted (or template, if no key / quota exhausted) interpretation
python ai_interpreter.py --use-llm

# 3. Generate the severity-scored, professional report
python report_generator.py
```

Outputs: `scan_results.json`, `scan_results_ai.json`,
`vulnerability_report.md`, `vulnerability_report.json`.

## Regression commands

Run these after any code change, in order:

```powershell
python lab_dns_server.py --selftest
python lab_http_server.py --selftest
python subtakeover_scanner.py --start-lab --evaluate
python ai_interpreter.py --selftest
python report_generator.py --selftest
```

Expected: all selftests report every check as `PASS`, and
`--evaluate` reports `EVALUATION ALL MATCH` (exit code 0).

## Lab scenarios

| Subdomain | Setup | Expected verdict |
|---|---|---|
| `portal.pms-lab.test` | Plain A record, healthy app | `NOT_VULNERABLE` |
| `docs.pms-lab.test` | CNAME to a dangling (NXDOMAIN) Azure App Service | `CONFIRMED` |
| `blog.pms-lab.test` | CNAME to an S3 bucket that no longer exists (`NoSuchBucket`) | `CONFIRMED` |
| `tenant.pms-lab.test` | CNAME to a claimed, healthy GitHub Pages site (false-positive trap) | `NOT_VULNERABLE` |
| `legacy.pms-lab.test` | CNAME to Heroku, generic 404, no provider signature | `AMBIGUOUS` (goes to the LLM) |
| `example.com` | Outside the authorized lab zone | `SKIPPED_UNAUTHORIZED` |

## Stage 5 - Severity scoring

Severity is derived from the scanner verdict (`CONFIRMED` > `LIKELY` >
`AMBIGUOUS`; `NOT_VULNERABLE`/`SKIPPED_UNAUTHORIZED`/`ERROR` excluded), then
adjusted up by simulated lab context (`sensitivity: high`,
`cookie_scope: parent` in `lab_config.py` - my own lab-design assumption,
not real-world data). The scanner verdict is always authoritative; the
AI/template interpretation is advisory-only and never changes it. See
`vulnerability_report.md` for the full per-finding reasoning.

## Stage 6 - False-positive tuning (before/after)

**Before (v1.0-baseline):** the scanner treated any provider fingerprint
text found anywhere in the HTTP response body, at any status code, as a
confirmed takeover. This produced a false positive on
`tenant.pms-lab.test`: its page is a normal, claimed GitHub Pages site
(HTTP 200) whose content happens to *mention* the GitHub "unclaimed site"
error message in a security-notes paragraph - see
`scan_results_baseline.json`.

**After (v1.1-tuned):** a fingerprint now only counts when the text is
found **and** the HTTP status matches the provider's documented
"unclaimed resource" status (`http_fingerprint_status` in
`fingerprints.json`, currently `404` for GitHub Pages/S3/Heroku - my own
assumption, see `LIMITATIONS.md`). `tenant.pms-lab.test` (HTTP 200) no
longer matches, and `--evaluate` now reports `ALL MATCH` across all five
lab scenarios. See `scan_results.json` for the tuned run.

## Deliverables checklist

- [x] Detection tool source (`subtakeover_scanner.py`, `ai_interpreter.py`,
      `report_generator.py`, lab infrastructure)
- [x] Per-URL vulnerability report: Detected (Y/N) | Evidence | Severity |
      Remediation (`vulnerability_report.md` / `.json`)
- [x] Limitations and false-positive handling documented
      (`LIMITATIONS.md`)
- [x] Authorization note confirming lab-only testing
      (`AUTHORIZATION_NOTE.md`)
- [x] Tested for both true positives (docs/blog/legacy) and a false
      positive (tenant - found, documented, fixed in Stage 6)
- [x] Severity with clear reasoning (`report_generator.py` +
      `vulnerability_report.md`)
- [x] AI-assisted interpretation clearly labelled, never overriding the
      scanner verdict
- [ ] Code and report pushed to GitHub (see below)

## Pushing to GitHub

Repository: `subdomain-takeover-detector-pms-lab` (GitHub user
`Maryam-Yaqoob`).

```powershell
git init
git add .
git commit -m "AI-assisted subdomain takeover exposure detector (Week 4)"
git branch -M main
git remote add origin https://github.com/Maryam-Yaqoob/subdomain-takeover-detector-pms-lab.git
git push -u origin main
```
