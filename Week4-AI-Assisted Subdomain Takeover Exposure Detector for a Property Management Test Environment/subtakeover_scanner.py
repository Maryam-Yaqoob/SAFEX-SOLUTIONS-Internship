"""
subtakeover_scanner.py - Subdomain Takeover Exposure detector (v1 baseline).

AUTHORIZED LAB ONLY. This tool is hard-wired to the local lab:
  * DNS queries go only to the lab DNS server (lab_config.DNS_HOST:DNS_PORT).
  * HTTP requests go only to the lab web server (lab_config.HTTP_HOST:HTTP_PORT)
    with the target name in the Host header.
  * Any target outside lab_config.LAB_DOMAIN is refused BEFORE any lookup.

Detection method (per target):
  1. Follow the CNAME chain using the lab resolver.
  2. Match the chain against known claimable providers (fingerprints.json).
  3. If the final CNAME target does not exist (NXDOMAIN) -> dangling record.
  4. Otherwise fetch the page and look for the provider's "unclaimed resource"
     error signature.
Verdicts: CONFIRMED, LIKELY, AMBIGUOUS, NOT_VULNERABLE, ERROR,
SKIPPED_UNAUTHORIZED. AMBIGUOUS cases are meant for the LLM stage (Stage 4).

Usage:
    python subtakeover_scanner.py --start-lab             # scan and print summary
    python subtakeover_scanner.py --start-lab --evaluate  # also compare with lab ground truth

ASSUMPTIONS (flagged):
  * v1 is a deliberately simple BASELINE: a provider signature found anywhere in
    the response body counts as a match, regardless of HTTP status. Stage 6 tests
    it against the patched page and tunes it. With --evaluate, one known false
    positive (tenant.pms-lab.test) is EXPECTED from this baseline.
  * Only A/CNAME DNS records and plain HTTP on the lab port are checked.
  * --start-lab runs the lab DNS and HTTP servers inside this process. Without it,
    start lab_dns_server.py and lab_http_server.py yourself first.
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

import lab_config

SCANNER_VERSION = "1.1-tuned"
MAX_CNAME_HOPS = 8
HTTP_TIMEOUT = 5
SNIPPET_CHARS = 300
POSITIVE_VERDICTS = {"CONFIRMED", "LIKELY"}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- inputs

def load_fingerprints(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["providers"]


def load_targets(path):
    """Read targets (URL or bare hostname per line; '#' starts a comment)."""
    targets = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = urlparse(line if "://" in line else "http://" + line)
            targets.append((line, (parsed.hostname or "").lower()))
    return targets


def is_authorized(hostname):
    """Authorization guard: only the lab zone may be scanned."""
    domain = lab_config.LAB_DOMAIN
    return hostname == domain or hostname.endswith("." + domain)


# ---------------------------------------------------------------- DNS

def make_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [lab_config.DNS_HOST]
    resolver.port = lab_config.DNS_PORT
    resolver.lifetime = 3
    return resolver


def resolve_cname_chain(resolver, hostname):
    """Return (chain, last_name, status). status: None, 'NXDOMAIN', 'LOOP', 'ERROR:<type>'."""
    chain, name = [], hostname
    for _ in range(MAX_CNAME_HOPS):
        try:
            answer = resolver.resolve(name, "CNAME")
        except dns.resolver.NoAnswer:
            return chain, name, None
        except dns.resolver.NXDOMAIN:
            return chain, name, "NXDOMAIN"
        except dns.exception.DNSException as exc:
            return chain, name, f"ERROR:{exc.__class__.__name__}"
        name = str(answer[0].target).rstrip(".").lower()
        chain.append(name)
    return chain, name, "LOOP"


def resolve_a(resolver, name):
    """Return (state, addresses). state: OK, NXDOMAIN, NODATA, ERROR."""
    try:
        return "OK", [r.address for r in resolver.resolve(name, "A")]
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", []
    except dns.resolver.NoAnswer:
        return "NODATA", []
    except dns.exception.DNSException as exc:
        return "ERROR", [exc.__class__.__name__]


# ---------------------------------------------------------------- HTTP / matching

def match_provider(chain, providers):
    for hop in chain:
        for provider in providers:
            for suffix in provider["cname_suffixes"]:
                if hop == suffix or hop.endswith("." + suffix):
                    return provider
    return None


def http_probe(hostname):
    """GET the lab web server with Host=hostname. Returns (info, body)."""
    url = f"http://{lab_config.HTTP_HOST}:{lab_config.HTTP_PORT}/"
    try:
        resp = requests.get(
            url, headers={"Host": hostname}, timeout=HTTP_TIMEOUT, allow_redirects=False
        )
    except requests.RequestException as exc:
        return {"error": exc.__class__.__name__}, ""
    info = {
        "status": resp.status_code,
        "server": resp.headers.get("Server", ""),
        "body_length": len(resp.text),
        "body_snippet": resp.text[:SNIPPET_CHARS],
    }
    return info, resp.text


def find_fingerprint(provider, status, body):
    """v1 baseline: case-insensitive substring match anywhere in the body."""
    lowered = body.lower()
    allowed_statuses = provider.get("http_fingerprint_status", [])
    for fingerprint in provider["http_fingerprints"]:
        if fingerprint.lower() in lowered:
            if status in allowed_statuses:
                return fingerprint, None
            return None, (
                f"Fingerprint text {fingerprint!r} was present in the body but "
                f"HTTP status {status} is not in the expected unclaimed-resource "
                f"status(es) {allowed_statuses} for {provider['name']}; not counted "
                f"as a match (Stage 6 tuning to prevent false positives)."
            )
    return None, None


# ---------------------------------------------------------------- scanning

def scan_target(raw, hostname, resolver, providers):
    result = {
        "target": raw,
        "hostname": hostname,
        "verdict": None,
        "provider": None,
        "cname_chain": [],
        "dns_state": None,
        "http": None,
        "matched_fingerprint": None,
        "evidence": [],
    }
    ev = result["evidence"]

    if not is_authorized(hostname):
        result["verdict"] = "SKIPPED_UNAUTHORIZED"
        ev.append(f"{hostname!r} is outside the authorized lab zone {lab_config.LAB_DOMAIN!r}; no lookups made.")
        return result

    chain, last_name, status = resolve_cname_chain(resolver, hostname)
    result["cname_chain"] = chain

    if not chain:
        if status == "NXDOMAIN":
            result["verdict"] = "NOT_VULNERABLE"
            result["dns_state"] = "NXDOMAIN"
            ev.append("Subdomain has no DNS record at all.")
            return result
        state, addrs = resolve_a(resolver, hostname)
        result["dns_state"] = state
        result["verdict"] = "NOT_VULNERABLE" if state == "OK" else "ERROR"
        ev.append(f"No CNAME; resolves directly ({state}: {', '.join(addrs) or 'none'}). No third-party dependency.")
        return result

    ev.append("CNAME chain: " + " -> ".join([hostname] + chain))
    provider = match_provider(chain, providers)
    if provider is None:
        result["verdict"] = "NOT_VULNERABLE"
        ev.append("CNAME target is not on the known claimable-provider list (see limitations).")
        return result
    result["provider"] = provider["name"]
    ev.append(f"Target belongs to provider: {provider['name']}.")

    if status == "NXDOMAIN":
        dns_state = "NXDOMAIN"
    elif status is not None:
        result["verdict"] = "ERROR"
        ev.append(f"CNAME chain resolution problem: {status}.")
        return result
    else:
        dns_state, _ = resolve_a(resolver, last_name)
    result["dns_state"] = dns_state

    if dns_state == "NXDOMAIN":
        ev.append(f"CNAME target {last_name!r} does not exist (NXDOMAIN): dangling record.")
        if provider["nxdomain_means_takeover"]:
            result["verdict"] = "CONFIRMED"
            ev.append(f"{provider['name']} names can be claimed when unregistered, so this is takeover-exposed.")
        else:
            result["verdict"] = "LIKELY"
            ev.append(f"NXDOMAIN is not the usual takeover signal for {provider['name']}; needs manual review.")
        return result
    if dns_state != "OK":
        result["verdict"] = "ERROR"
        ev.append(f"CNAME target lookup returned {dns_state}.")
        return result

    ev.append(f"CNAME target {last_name!r} resolves; probing HTTP.")
    info, body = http_probe(hostname)
    result["http"] = info
    if "error" in info:
        result["verdict"] = "AMBIGUOUS"
        ev.append(f"HTTP request failed ({info['error']}); cannot inspect the page.")
        return result

    ev.append(f"HTTP {info['status']} from Server={info['server']!r}, {info['body_length']} bytes.")
    fingerprint, status_mismatch_note = find_fingerprint(provider, info["status"], body)
    if status_mismatch_note:
        ev.append(status_mismatch_note)
    if fingerprint:
        result["verdict"] = "CONFIRMED"
        result["matched_fingerprint"] = fingerprint
        ev.append(f"Response body contains the unclaimed-resource signature {fingerprint!r}.")
    elif info["status"] >= 400:
        result["verdict"] = "AMBIGUOUS"
        ev.append("Error status but no known provider signature; needs interpretation.")
    else:
        result["verdict"] = "NOT_VULNERABLE"
        ev.append("Page served normally and no unclaimed-resource signature found.")
    return result


# ---------------------------------------------------------------- lab control

def start_lab():
    """Run the lab DNS and HTTP servers in this process, quietly."""
    from dnslib.server import DNSLogger, DNSServer

    import lab_dns_server
    import lab_http_server

    dns_server = DNSServer(
        lab_dns_server.LabResolver(),
        port=lab_config.DNS_PORT,
        address=lab_config.DNS_HOST,
        tcp=False,
        logger=DNSLogger(log="-request,-reply,-truncated,-error", prefix=False),
    )
    dns_server.start_thread()

    class QuietHandler(lab_http_server.LabHandler):
        def log_message(self, fmt, *args):
            pass

    http_server = ThreadingHTTPServer((lab_config.HTTP_HOST, lab_config.HTTP_PORT), QuietHandler)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    time.sleep(0.5)
    return dns_server, http_server


def stop_lab(dns_server, http_server):
    dns_server.stop()
    http_server.shutdown()
    http_server.server_close()


# ---------------------------------------------------------------- output

def print_summary(results):
    print(f"\n{'TARGET':<26}{'VERDICT':<22}{'PROVIDER':<30}KEY EVIDENCE")
    print("-" * 110)
    for r in results:
        print(f"{r['hostname']:<26}{r['verdict']:<22}{(r['provider'] or '-'):<30}{r['evidence'][-1]}")


def evaluate(results):
    """Compare verdicts with lab_config ground truth. Returns exit code."""
    expected = {s["name"]: s["expected"] for s in lab_config.SUBDOMAINS}
    print("\nEVALUATION against lab ground truth")
    print("-" * 70)
    mismatches = 0
    for r in results:
        want = expected.get(r["hostname"])
        if want is None:
            continue
        got = r["verdict"]
        if got == want:
            outcome = "MATCH"
        elif got in POSITIVE_VERDICTS and want == "NOT_VULNERABLE":
            outcome = "FALSE POSITIVE"
        elif got == "NOT_VULNERABLE" and want in POSITIVE_VERDICTS:
            outcome = "FALSE NEGATIVE"
        else:
            outcome = "MISMATCH"
        mismatches += 0 if outcome == "MATCH" else 1
        print(f"{r['hostname']:<26}expected={want:<16}got={got:<16}{outcome}")
    print("-" * 70)
    print("EVALUATION", "ALL MATCH" if mismatches == 0 else f"{mismatches} mismatch(es)")
    return 0 if mismatches == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover exposure scanner (authorized lab only)")
    parser.add_argument("--targets", default=os.path.join(BASE_DIR, "targets.txt"))
    parser.add_argument("--fingerprints", default=os.path.join(BASE_DIR, "fingerprints.json"))
    parser.add_argument("--output", default=os.path.join(BASE_DIR, "scan_results.json"))
    parser.add_argument("--start-lab", action="store_true", help="start lab DNS + HTTP servers in-process")
    parser.add_argument("--evaluate", action="store_true", help="compare verdicts with lab ground truth")
    args = parser.parse_args()

    providers = load_fingerprints(args.fingerprints)
    targets = load_targets(args.targets)
    print(f"Subdomain Takeover scanner {SCANNER_VERSION} - AUTHORIZED LAB ONLY ({lab_config.LAB_DOMAIN})")

    lab = start_lab() if args.start_lab else None
    try:
        resolver = make_resolver()
        results = [scan_target(raw, host, resolver, providers) for raw, host in targets]
    finally:
        if lab:
            stop_lab(*lab)

    print_summary(results)
    payload = {
        "scanner_version": SCANNER_VERSION,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lab_domain": lab_config.LAB_DOMAIN,
        "results": results,
    }
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nWrote {len(results)} results to {args.output}")

    sys.exit(evaluate(results) if args.evaluate else 0)


if __name__ == "__main__":
    main()
