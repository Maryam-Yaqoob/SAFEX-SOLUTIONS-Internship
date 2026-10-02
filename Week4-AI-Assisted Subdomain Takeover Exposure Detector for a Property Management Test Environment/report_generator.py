"""
report_generator.py - Stage 5: severity scoring + professional vulnerability
report generator for the Subdomain Takeover Exposure Detector lab.

Reads a scan_results_ai.json-shaped file (scanner verdict + AI interpretation
block per finding) and lab_config.py (for per-subdomain sensitivity /
cookie_scope context), and writes:
  - a Markdown report:  Vulnerability Detected (Y/N) | Evidence | Severity |
                        Recommended Remediation
  - a machine-readable JSON report with the same information plus the raw
    scanner verdict and the AI suggestion/confidence kept as separate,
    clearly labelled advisory fields.

The SCANNER VERDICT IS ALWAYS AUTHORITATIVE. The LLM/template
"ai_interpretation" block is surfaced only as an advisory next_steps /
explanation aid and is never allowed to change Severity or Vulnerability
Detected. This mirrors the design already used in ai_interpreter.py and
subtakeover_scanner.py.

ASSUMPTIONS (flagged; my own lab design / engineering judgement, not
real-world data):

  1. lab_config.py's SUBDOMAINS entries carry "sensitivity"
     ("high"/"medium"/"low") and "cookie_scope" ("parent"/"host-only").
     These describe a *simulated* real-world context for severity scoring
     only (e.g. "this subdomain would be tenant-facing / carry auth
     cookies in a real deployment"). They are not derived from any real
     traffic, config, or measurement.

  2. The task's deliverable format asks for a strict "Vulnerability
     Detected (Y/N)" column, but the scanner has six possible verdicts
     (CONFIRMED, LIKELY, AMBIGUOUS, NOT_VULNERABLE, ERROR,
     SKIPPED_UNAUTHORIZED). These are mapped to the Y/N column as follows,
     because AMBIGUOUS/ERROR/SKIPPED_UNAUTHORIZED cannot honestly be
     forced into a bare Y or N:
        CONFIRMED, LIKELY          -> "Y"
        AMBIGUOUS                  -> "Y (Unconfirmed)"   (cautious default:
                                       treat as a potential exposure needing
                                       manual verification, consistent with
                                       the scanner's own template wording)
        NOT_VULNERABLE             -> "N"
        ERROR                      -> "N/A (Inconclusive)"
        SKIPPED_UNAUTHORIZED       -> "N/A (Out of Scope)"

  3. SKIPPED_UNAUTHORIZED targets (e.g. example.com) ARE included as a row
     in the report, explicitly marked out of scope, rather than silently
     omitted -- for transparency, so a reader cannot mistake "never
     scanned" for "checked and clean".

SEVERITY SCHEME (confirmed with the user before implementation):

  Step 1 - base severity from the scanner verdict:
      CONFIRMED             -> High
      LIKELY                -> Medium-High
      AMBIGUOUS             -> Medium
      NOT_VULNERABLE        -> Informational (no severity; nothing to fix)
      ERROR                 -> N/A (inconclusive, excluded from severity)
      SKIPPED_UNAUTHORIZED  -> N/A (out of scope, excluded from severity)

  Step 2 - adjust by subdomain sensitivity / cookie-scope context, but only
  when the base severity is Medium or higher (never invented for a host the
  scanner found NOT_VULNERABLE):
      - sensitivity == "high"       -> bump one level up
      - cookie_scope == "parent"    -> bump one level up
      (both can apply; capped at High - there is no level above High)

  Step 3 - every row gets a short written justification citing which rules
  fired (verdict + sensitivity + cookie-scope).

Usage:
    python report_generator.py
    python report_generator.py --input scan_results_ai.json --md-out vulnerability_report.md --json-out vulnerability_report.json
    python report_generator.py --selftest
"""

import argparse
import json
import sys
from datetime import datetime, timezone

DEFAULT_INPUT = "scan_results_ai.json"
DEFAULT_MD_OUT = "vulnerability_report.md"
DEFAULT_JSON_OUT = "vulnerability_report.json"

# Step 1: base severity per scanner verdict. None = excluded from severity scoring.
BASE_SEVERITY = {
    "CONFIRMED": "High",
    "LIKELY": "Medium-High",
    "AMBIGUOUS": "Medium",
    "NOT_VULNERABLE": "Informational",
    "ERROR": None,
    "SKIPPED_UNAUTHORIZED": None,
}

# Ordered so we can "bump one level up", capped at the top.
SEVERITY_LADDER = ["Informational", "Low", "Medium", "Medium-High", "High"]

# Vulnerability Detected (Y/N) mapping - see ASSUMPTION 2 above.
VULN_DETECTED = {
    "CONFIRMED": "Y",
    "LIKELY": "Y",
    "AMBIGUOUS": "Y (Unconfirmed)",
    "NOT_VULNERABLE": "N",
    "ERROR": "N/A (Inconclusive)",
    "SKIPPED_UNAUTHORIZED": "N/A (Out of Scope)",
}

REMEDIATION_BY_VERDICT = {
    "CONFIRMED": "Delete or repoint the dangling DNS record immediately. "
                 "If the resource must remain, re-claim it on the provider "
                 "before restoring the record, then audit other subdomains "
                 "for the same decommissioning gap.",
    "LIKELY": "Treat as a likely takeover: verify manually, then delete or "
              "repoint the DNS record. Prioritise verification given the "
              "high probability of exposure.",
    "AMBIGUOUS": "Manually verify the claim status of the third-party "
                 "resource before deciding; the generic response could not "
                 "be fingerprinted automatically. Do not leave unreviewed.",
    "NOT_VULNERABLE": "No remediation required. Keep this subdomain in the "
                       "periodic DNS-inventory / decommission audit.",
    "ERROR": "Re-run the scan for this target; no verdict could be produced "
             "due to a scanner error. Do not treat as cleared.",
    "SKIPPED_UNAUTHORIZED": "No action: this target is outside the "
                            "authorized scan scope and was never queried. "
                            "Remove it from targets.txt if it should never "
                            "be scanned.",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_sensitivity_map(lab_config_module=None):
    """
    Build {hostname: {"sensitivity": ..., "cookie_scope": ...}} from
    lab_config.SUBDOMAINS. Falls back to an empty dict (no adjustment) if
    lab_config cannot be imported or a host has no entry - this keeps the
    report generator usable even before Stage-5 config fields exist,
    rather than crashing.
    """
    if lab_config_module is None:
        try:
            import lab_config as lab_config_module
        except ImportError:
            return {}
    out = {}
    for entry in getattr(lab_config_module, "SUBDOMAINS", []):
        name = entry.get("name")
        if name:
            out[name] = {
                "sensitivity": entry.get("sensitivity"),
                "cookie_scope": entry.get("cookie_scope"),
            }
    return out


def bump_severity(base, levels=1):
    if base not in SEVERITY_LADDER:
        return base
    idx = SEVERITY_LADDER.index(base)
    idx = min(idx + levels, len(SEVERITY_LADDER) - 1)
    return SEVERITY_LADDER[idx]


def compute_severity(verdict, sensitivity, cookie_scope):
    """
    Returns (severity, reasoning_str). severity is None for verdicts
    excluded from severity scoring (ERROR, SKIPPED_UNAUTHORIZED).
    Adjustment (Step 2) only applies when the base is Medium or higher,
    per the confirmed scheme - never invented for NOT_VULNERABLE/None.
    """
    base = BASE_SEVERITY.get(verdict)
    if base is None:
        return None, f"Verdict '{verdict}' is excluded from severity scoring (inconclusive or out of scope)."
    if base == "Informational":
        return base, "Scanner verdict is NOT_VULNERABLE; no exposure to rate."

    severity = base
    reasons = [f"Base severity '{base}' from scanner verdict '{verdict}'."]
    bumps = 0
    if sensitivity == "high":
        bumps += 1
        reasons.append("Subdomain sensitivity is 'high' (tenant-facing/auth/payment context) -> severity raised one level.")
    if cookie_scope == "parent":
        bumps += 1
        reasons.append("Cookie scope is 'parent' (parent-domain cookies assumed in scope) -> severity raised one level.")
    if bumps:
        severity = bump_severity(base, bumps)
        if severity == base:
            reasons.append(f"Already at the top of the severity scale ('{base}'); no further increase possible.")
        else:
            reasons.append(f"Final severity after adjustment: '{severity}'.")
    else:
        reasons.append("No sensitivity/cookie-scope adjustment applied (low/medium sensitivity, host-only cookies).")
    return severity, " ".join(reasons)


def format_evidence(finding):
    ev = finding.get("evidence") or []
    if not ev:
        return "(no evidence recorded)"
    return "; ".join(ev)


def format_ai_block(finding):
    """
    Returns a short, clearly-labelled string summarising the advisory AI
    (or template) interpretation, for inclusion in the remediation column.
    Never used to change verdict/severity - advisory only.
    """
    ai = finding.get("ai_interpretation") or {}
    source = ai.get("source", "Template explanation (no LLM used)")
    steps = ai.get("next_steps") or []
    parts = [f"[{source}]"]
    if ai.get("confidence"):
        parts.append(f"(confidence: {ai['confidence']})")
    if ai.get("suggested_verdict"):
        parts.append(f"Advisory suggestion: {ai['suggested_verdict']} - does NOT override the scanner verdict.")
    if steps:
        parts.append("Suggested next steps: " + "; ".join(steps))
    if ai.get("note"):
        parts.append(f"Note: {ai['note']}")
    return " ".join(parts)


def build_report_rows(scan_data, sensitivity_map):
    rows = []
    for finding in scan_data.get("results", []):
        hostname = finding.get("hostname", finding.get("target", "unknown"))
        verdict = finding.get("verdict", "ERROR")
        ctx = sensitivity_map.get(hostname, {})
        sensitivity = ctx.get("sensitivity")
        cookie_scope = ctx.get("cookie_scope")

        severity, severity_reason = compute_severity(verdict, sensitivity, cookie_scope)
        vuln_detected = VULN_DETECTED.get(verdict, "N/A (Unknown Verdict)")
        base_remediation = REMEDIATION_BY_VERDICT.get(verdict, "Manually review this finding.")
        ai_summary = format_ai_block(finding)

        rows.append({
            "hostname": hostname,
            "target": finding.get("target"),
            "scanner_verdict": verdict,
            "vulnerability_detected": vuln_detected,
            "evidence": format_evidence(finding),
            "severity": severity,
            "severity_reasoning": severity_reason,
            "sensitivity_context": sensitivity,
            "cookie_scope_context": cookie_scope,
            "recommended_remediation": base_remediation,
            "ai_advisory": ai_summary,
            "ai_source_label": (finding.get("ai_interpretation") or {}).get("source"),
            "ai_confidence": (finding.get("ai_interpretation") or {}).get("confidence"),
            "ai_suggested_verdict": (finding.get("ai_interpretation") or {}).get("suggested_verdict"),
        })
    return rows


def render_markdown(rows, scan_data):
    lines = []
    lines.append("# Subdomain Takeover Exposure - Vulnerability Report")
    lines.append("")
    lines.append(f"- Lab domain: `{scan_data.get('lab_domain', 'unknown')}`")
    lines.append(f"- Scanner version: `{scan_data.get('scanner_version', 'unknown')}`")
    lines.append(f"- Scan time (UTC): `{scan_data.get('scan_time_utc', 'unknown')}`")
    lines.append(f"- Report generated (UTC): `{datetime.now(timezone.utc).isoformat()}`")
    lines.append("")
    lines.append("> The scanner verdict is authoritative. Any AI-assisted or template "
                 "advisory text below is clearly labelled and does not change the "
                 "verdict or severity.")
    lines.append("")
    lines.append("| Host | Vulnerability Detected (Y/N) | Evidence | Severity | Recommended Remediation |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        evidence = r["evidence"].replace("|", "\\|")
        remediation = (r["recommended_remediation"] + " " + r["ai_advisory"]).replace("|", "\\|")
        severity_cell = r["severity"] if r["severity"] else "N/A"
        lines.append(f"| {r['hostname']} | {r['vulnerability_detected']} | {evidence} | {severity_cell} | {remediation} |")
    lines.append("")
    lines.append("## Severity reasoning (per finding)")
    lines.append("")
    for r in rows:
        lines.append(f"- **{r['hostname']}** ({r['scanner_verdict']}): {r['severity_reasoning']}")
    lines.append("")
    lines.append("## Advisory AI / template interpretation labels (per finding)")
    lines.append("")
    for r in rows:
        lines.append(f"- **{r['hostname']}**: source = `{r['ai_source_label']}`"
                      + (f", confidence = `{r['ai_confidence']}`" if r['ai_confidence'] else "")
                      + (f", suggested_verdict = `{r['ai_suggested_verdict']}` (advisory only)" if r['ai_suggested_verdict'] else ""))
    return "\n".join(lines) + "\n"


def build_json_report(rows, scan_data):
    return {
        "lab_domain": scan_data.get("lab_domain"),
        "scanner_version": scan_data.get("scanner_version"),
        "scan_time_utc": scan_data.get("scan_time_utc"),
        "report_generated_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Scanner verdict is authoritative. ai_source_label/ai_confidence/"
                "ai_suggested_verdict are advisory-only fields and never override "
                "vulnerability_detected or severity.",
        "findings": rows,
    }


def generate(input_path, md_out_path, json_out_path, lab_config_module=None):
    scan_data = load_json(input_path)
    sensitivity_map = load_sensitivity_map(lab_config_module)
    rows = build_report_rows(scan_data, sensitivity_map)
    md = render_markdown(rows, scan_data)
    js = build_json_report(rows, scan_data)
    if md_out_path:
        with open(md_out_path, "w", encoding="utf-8") as f:
            f.write(md)
    if json_out_path:
        with open(json_out_path, "w", encoding="utf-8") as f:
            json.dump(js, f, indent=2)
    return rows, md, js


# --------------------------------------------------------------------------- #
# Selftest
# --------------------------------------------------------------------------- #

def run_selftest():
    passed = 0
    failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[FAIL] {name}")
            failed += 1

    # --- severity ladder / bump ---
    check("bump_severity Medium -> Medium-High", bump_severity("Medium", 1) == "Medium-High")
    check("bump_severity High capped at High", bump_severity("High", 1) == "High")
    check("bump_severity two bumps Medium -> High", bump_severity("Medium", 2) == "High")

    # --- compute_severity: base cases ---
    sev, _ = compute_severity("CONFIRMED", None, None)
    check("CONFIRMED base severity High (no context)", sev == "High")

    sev, _ = compute_severity("NOT_VULNERABLE", "high", "parent")
    check("NOT_VULNERABLE stays Informational even with high sensitivity", sev == "Informational")

    sev, _ = compute_severity("ERROR", "high", "parent")
    check("ERROR excluded from severity (None) regardless of context", sev is None)

    sev, _ = compute_severity("SKIPPED_UNAUTHORIZED", "high", "parent")
    check("SKIPPED_UNAUTHORIZED excluded from severity (None)", sev is None)

    # --- compute_severity: adjustment logic ---
    sev, _ = compute_severity("AMBIGUOUS", "low", "host-only")
    check("AMBIGUOUS + low/host-only stays Medium (no bump)", sev == "Medium")

    sev, _ = compute_severity("AMBIGUOUS", "high", "host-only")
    check("AMBIGUOUS + high sensitivity bumps to Medium-High", sev == "Medium-High")

    sev, _ = compute_severity("LIKELY", "high", "parent")
    check("LIKELY + high + parent double-bumps to High", sev == "High")

    sev, _ = compute_severity("CONFIRMED", "high", "parent")
    check("CONFIRMED + high + parent capped at High (already max)", sev == "High")

    # --- vulnerability detected mapping ---
    check("VULN_DETECTED CONFIRMED -> Y", VULN_DETECTED["CONFIRMED"] == "Y")
    check("VULN_DETECTED AMBIGUOUS -> Y (Unconfirmed)", VULN_DETECTED["AMBIGUOUS"] == "Y (Unconfirmed)")
    check("VULN_DETECTED NOT_VULNERABLE -> N", VULN_DETECTED["NOT_VULNERABLE"] == "N")
    check("VULN_DETECTED SKIPPED_UNAUTHORIZED -> N/A (Out of Scope)", VULN_DETECTED["SKIPPED_UNAUTHORIZED"] == "N/A (Out of Scope)")
    check("VULN_DETECTED ERROR -> N/A (Inconclusive)", VULN_DETECTED["ERROR"] == "N/A (Inconclusive)")

    # --- end-to-end with a mock scan_data (in-memory, no lab_config needed) ---
    mock_scan = {
        "lab_domain": "pms-lab.test",
        "scanner_version": "test",
        "scan_time_utc": "2026-01-01T00:00:00+00:00",
        "results": [
            {
                "hostname": "confirmed-high.pms-lab.test",
                "target": "http://confirmed-high.pms-lab.test",
                "verdict": "CONFIRMED",
                "evidence": ["dangling CNAME"],
                "ai_interpretation": {"source": "AI-assisted interpretation", "model": "x",
                                       "confidence": "high", "suggested_verdict": None,
                                       "next_steps": ["fix it"], "note": None},
            },
            {
                "hostname": "notvuln.pms-lab.test",
                "target": "http://notvuln.pms-lab.test",
                "verdict": "NOT_VULNERABLE",
                "evidence": ["healthy"],
                "ai_interpretation": {"source": "Template explanation (no LLM used)", "model": None,
                                       "confidence": None, "suggested_verdict": None,
                                       "next_steps": [], "note": None},
            },
            {
                "hostname": "amb.pms-lab.test",
                "target": "http://amb.pms-lab.test",
                "verdict": "AMBIGUOUS",
                "evidence": ["generic 404"],
                "ai_interpretation": {"source": "AI-assisted interpretation", "model": "x",
                                       "confidence": "medium", "suggested_verdict": "NEEDS_MANUAL_REVIEW",
                                       "next_steps": ["check manually"], "note": None},
            },
            {
                "hostname": "example.com",
                "target": "http://example.com",
                "verdict": "SKIPPED_UNAUTHORIZED",
                "evidence": ["out of zone"],
                "ai_interpretation": {"source": "Template explanation (no LLM used)", "model": None,
                                       "confidence": None, "suggested_verdict": None,
                                       "next_steps": [], "note": "Unauthorized target: never sent to the LLM."},
            },
            {
                "hostname": "broken.pms-lab.test",
                "target": "http://broken.pms-lab.test",
                "verdict": "ERROR",
                "evidence": ["connection refused"],
                "ai_interpretation": {"source": "Template explanation (no LLM used)", "model": None,
                                       "confidence": None, "suggested_verdict": None,
                                       "next_steps": [], "note": None},
            },
        ],
    }
    mock_sensitivity = {
        "confirmed-high.pms-lab.test": {"sensitivity": "high", "cookie_scope": "parent"},
        "notvuln.pms-lab.test": {"sensitivity": "high", "cookie_scope": "parent"},
        "amb.pms-lab.test": {"sensitivity": "low", "cookie_scope": "host-only"},
    }
    rows = build_report_rows(mock_scan, mock_sensitivity)
    by_host = {r["hostname"]: r for r in rows}

    check("end-to-end: 5 rows produced", len(rows) == 5)
    check("end-to-end: confirmed-high severity High", by_host["confirmed-high.pms-lab.test"]["severity"] == "High")
    check("end-to-end: notvuln severity Informational despite high sensitivity", by_host["notvuln.pms-lab.test"]["severity"] == "Informational")
    check("end-to-end: notvuln vuln_detected N", by_host["notvuln.pms-lab.test"]["vulnerability_detected"] == "N")
    check("end-to-end: amb severity stays Medium (low sensitivity, no bump)", by_host["amb.pms-lab.test"]["severity"] == "Medium")
    check("end-to-end: amb vuln_detected Y (Unconfirmed)", by_host["amb.pms-lab.test"]["vulnerability_detected"] == "Y (Unconfirmed)")
    check("end-to-end: example.com severity None/N/A", by_host["example.com"]["severity"] is None)
    check("end-to-end: example.com vuln_detected N/A (Out of Scope)", by_host["example.com"]["vulnerability_detected"] == "N/A (Out of Scope)")
    check("end-to-end: broken.pms-lab.test (ERROR, no sensitivity map entry) severity None", by_host["broken.pms-lab.test"]["severity"] is None)
    check("end-to-end: broken.pms-lab.test vuln_detected N/A (Inconclusive)", by_host["broken.pms-lab.test"]["vulnerability_detected"] == "N/A (Inconclusive)")

    # --- AI advisory never overrides verdict/severity (spot check) ---
    check("AI suggested_verdict for amb is advisory only, verdict stays AMBIGUOUS",
          by_host["amb.pms-lab.test"]["scanner_verdict"] == "AMBIGUOUS")

    # --- markdown rendering doesn't crash and contains the required columns ---
    md = render_markdown(rows, mock_scan)
    check("markdown contains required header columns",
          "Vulnerability Detected (Y/N)" in md and "Evidence" in md and "Severity" in md and "Recommended Remediation" in md)
    check("markdown contains all 5 hostnames", all(h in md for h in by_host))

    # --- missing lab_config import fallback (no crash, empty sensitivity map) ---
    empty_map = load_sensitivity_map(lab_config_module=type("Empty", (), {"SUBDOMAINS": []})())
    check("load_sensitivity_map handles empty SUBDOMAINS without crashing", empty_map == {})

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Generate the Stage 5 severity + vulnerability report.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to scan_results_ai.json (default: %(default)s)")
    parser.add_argument("--md-out", default=DEFAULT_MD_OUT, help="Markdown output path (default: %(default)s)")
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT, help="JSON output path (default: %(default)s)")
    parser.add_argument("--selftest", action="store_true", help="Run the offline selftest and exit.")
    args = parser.parse_args()

    if args.selftest:
        ok = run_selftest()
        sys.exit(0 if ok else 1)

    rows, md, js = generate(args.input, args.md_out, args.json_out)
    print(f"Wrote {args.md_out} and {args.json_out} ({len(rows)} findings).")


if __name__ == "__main__":
    main()
