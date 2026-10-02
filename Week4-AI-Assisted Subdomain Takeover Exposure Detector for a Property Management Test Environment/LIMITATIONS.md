# Limitations

This document lists the known limitations of the AI-Assisted Subdomain
Takeover Exposure Detector, honestly, so results are not mistaken for a
complete or production-grade security assessment.

## 1. Detection scope

- Only **A** and **CNAME** DNS records and plain **HTTP** (not HTTPS) on the
  lab port are checked. NS-record takeovers, MX-record takeovers, and
  expired-parent-domain takeovers (see
  https://0xpatrik.com/subdomain-takeover-ns/) are **not** covered.
- Authenticated pages, pages behind a WAF, or pages that require specific
  headers/cookies to reach the "unclaimed resource" error are not modelled
  and would not be detected correctly by this tool.
- Only four providers are modelled in `fingerprints.json`: GitHub Pages,
  Amazon S3, Heroku, and Microsoft Azure App Service. Dozens of other
  claimable services exist (see the community list linked below) and are
  simply not recognised by this scanner.

## 2. Fingerprint accuracy (verified 2026-09-25)

`fingerprints.json` is modelled on the community
["can-i-take-over-xyz"](https://github.com/EdOverflow/can-i-take-over-xyz)
list. I manually compared our four providers against that list on
2026-09-25:

- **GitHub Pages** - community fingerprint is
  `There isn't a Github Pages site here.` (trailing period). Ours is
  `There isn't a GitHub Pages site here` (no period). Matching is
  case-insensitive substring, so this does not affect detection in the lab,
  but a byte-exact fingerprint should be used against a real target.
- **Amazon S3** - community fingerprint `The specified bucket does not
  exist` matches ours exactly (we also keep `NoSuchBucket`, the S3 XML
  error code, as a second variant).
- **Heroku** - community list marks Heroku as an **"Edge case"**, not a
  guaranteed vulnerability, with fingerprint `No such app`. This matches
  our design choice to treat a generic Heroku 404 (no fingerprint text) as
  `AMBIGUOUS` rather than `CONFIRMED`.
- **Microsoft Azure App Service** - community list gives no fingerprint
  text for Azure; it is a dangling-CNAME/NXDOMAIN case, which matches our
  implementation (empty `http_fingerprints`, detection relies on NXDOMAIN).
- The community list does **not** specify expected HTTP status codes per
  provider. The Stage 6 tuning (Section 4 below) assumes each provider's
  "unclaimed resource" page is served at HTTP 404; this is my own
  engineering judgement based on typical provider behaviour, not something
  independently verified against each provider's live infrastructure.
  Provider error pages and claim rules can change over time without
  notice; fingerprints and status assumptions should be re-verified before
  any real-world use.

## 3. Lab design, not a real environment

- All targets are hosted on a local, synthetic lab (`pms-lab.test` on
  127.0.0.1) that I designed myself, including the "ground truth" verdicts
  used for `--evaluate`. This proves the detection *logic* is correct
  against known-good and known-bad cases I constructed, but it is not
  proof the tool behaves identically against real, unpredictable
  third-party infrastructure.
- The `sensitivity` / `cookie_scope` fields in `lab_config.py`, used for
  Stage 5 severity scoring, are my own simulated context (e.g. "this
  subdomain would be tenant-facing in a real deployment"). They are not
  derived from any real traffic, configuration, or measurement.

## 4. Stage 6 tuning: status-gated fingerprint matching

- The original (v1.0) scanner treated a fingerprint substring match
  anywhere in the response body, at any HTTP status, as `CONFIRMED`. This
  produced a false positive on `tenant.pms-lab.test`: the GitHub Pages
  "unclaimed site" text appeared inside an ordinary HTTP 200 page (a
  security-notes paragraph mentioning the error message as an example).
- v1.1 requires the fingerprint text **and** a matching HTTP status
  (`http_fingerprint_status` in `fingerprints.json`, currently `[404]` for
  GitHub Pages/S3/Heroku) before counting it as a match. This fixed the
  false positive (`--evaluate` now reports `ALL MATCH`), but as noted in
  Section 2, the exact status codes are my own assumption, not verified
  against each provider's live behaviour.
- This is a deliberate, documented trade-off: a real "unclaimed resource"
  page served at an unexpected status code (e.g. 200 instead of 404) would
  now be missed (a false negative) rather than falsely confirmed. Given
  the choice between the two, I judged a transparently-flagged missed
  detection safer than a repeat false positive, but this should be
  revisited with real traffic data before production use.

## 5. LLM-assisted interpretation

- The `ai_interpretation` block (from `ai_interpreter.py`) is **advisory
  only**. It never changes the scanner's verdict or the severity score -
  the scanner verdict is always authoritative, by design.
- Every finding's `ai_interpretation.source` field is clearly labelled
  either `AI-assisted interpretation` (a real Gemini API call succeeded)
  or `Template explanation (no LLM used)` (offline fallback). A template
  explanation is never mislabelled as AI-assisted.
- The Google Gemini **free tier** used here is not reliable for a batch of
  calls: during development, calls failed intermittently with HTTP 503
  ("high demand"), and separately the **daily free-tier quota** was
  exhausted after very few calls in a single session (HTTP 429), causing
  most findings in some runs to fall back to templates. This is expected
  and handled gracefully (retry with backoff for transient 503/429 up to 3
  attempts, then a labelled template fallback), but it means the
  proportion of genuinely AI-interpreted findings in the final report can
  vary run to run depending on API availability at the time.
- The LLM is given only a short (<=300 character), neutralised snippet of
  each HTTP response body and is explicitly instructed to treat it as
  untrusted data, not instructions. Even so, LLM output should be treated
  as a hint for a human reviewer, not a verified fact.

## 6. False positives / false negatives

- True/false positive testing was done with `--evaluate` against the five
  lab scenarios I designed (see `AUTHORIZATION_NOTE.md` and the README).
  The one intentional false positive built into v1.0 (`tenant.pms-lab.test`)
  was found, documented, and fixed in Stage 6.
- No false negatives are known in the current five lab scenarios, but the
  tool has not been tested against a large, diverse set of real
  subdomains, so real-world false-negative behaviour (e.g. a provider not
  in `fingerprints.json`, or a status code other than 404) is unverified.
