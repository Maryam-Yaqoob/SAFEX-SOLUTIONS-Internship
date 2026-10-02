"""
lab_dns_server.py - Local DNS server for the Subdomain Takeover lab.

AUTHORIZED LAB ONLY. Answers queries for the fake zone in lab_config.py on
127.0.0.1:5353. It is authoritative-only: any name not defined in the lab
gets NXDOMAIN and nothing is ever forwarded to the real internet.

Usage:
    python lab_dns_server.py             # run the server (Ctrl+C to stop)
    python lab_dns_server.py --selftest  # start, verify every record, exit

ASSUMPTIONS (flagged):
  * UDP port 5353 on 127.0.0.1 is free on this machine (TCP is not served).
  * Only A and CNAME records are needed for the lab.
"""

import argparse
import sys
import time

from dnslib import CNAME, QTYPE, RCODE, RR, A
from dnslib.server import BaseResolver, DNSServer

import lab_config

TTL = 30


def _fqdn(name):
    """Normalise a name to lowercase with a trailing dot."""
    name = name.lower()
    return name if name.endswith(".") else name + "."


def build_zone():
    """Build (cname_table, a_table) from lab_config.SUBDOMAINS."""
    cnames, a_records = {}, {}
    for sub in lab_config.SUBDOMAINS:
        name = _fqdn(sub["name"])
        if sub["cname"] is None:
            a_records[name] = lab_config.LAB_IP
            continue
        target = _fqdn(sub["cname"])
        cnames[name] = target
        if sub["target_resolves"]:
            a_records[target] = lab_config.LAB_IP
        # target_resolves False -> target intentionally absent (dangling)
    return cnames, a_records


class LabResolver(BaseResolver):
    def __init__(self):
        self.cnames, self.a_records = build_zone()

    def resolve(self, request, handler):
        reply = request.reply()
        name = _fqdn(str(request.q.qname))
        qtype = QTYPE[request.q.qtype]

        for _ in range(8):  # follow at most 8 CNAME hops
            if name in self.cnames:
                target = self.cnames[name]
                reply.add_answer(RR(name, QTYPE.CNAME, ttl=TTL, rdata=CNAME(target)))
                if qtype == "CNAME":
                    return reply
                name = target
                continue
            if name in self.a_records:
                if qtype in ("A", "ANY"):
                    reply.add_answer(
                        RR(name, QTYPE.A, ttl=TTL, rdata=A(self.a_records[name]))
                    )
                return reply  # known name, no more data: NOERROR
            reply.header.rcode = RCODE.NXDOMAIN  # unknown / dangling target
            return reply

        reply.header.rcode = RCODE.SERVFAIL  # CNAME loop
        return reply


def start_server():
    server = DNSServer(
        LabResolver(),
        port=lab_config.DNS_PORT,
        address=lab_config.DNS_HOST,
        tcp=False,
    )
    server.start_thread()
    return server


def selftest():
    """Query every lab record and compare with lab_config. Returns exit code."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [lab_config.DNS_HOST]
    resolver.port = lab_config.DNS_PORT
    resolver.lifetime = 3

    def a_of(name):
        try:
            return [r.address for r in resolver.resolve(name, "A")]
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"

    failures = 0

    def check(label, actual, expected):
        nonlocal failures
        ok = actual == expected
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: got {actual!r}, expected {expected!r}")

    server = start_server()
    time.sleep(0.5)
    try:
        for sub in lab_config.SUBDOMAINS:
            name = sub["name"]
            if sub["cname"] is None:
                check(f"{name} A", a_of(name), [lab_config.LAB_IP])
                continue
            try:
                cname = str(resolver.resolve(name, "CNAME")[0].target).rstrip(".")
            except dns.exception.DNSException as exc:
                cname = f"ERROR {exc.__class__.__name__}"
            check(f"{name} CNAME", cname, sub["cname"])
            expected_a = [lab_config.LAB_IP] if sub["target_resolves"] else "NXDOMAIN"
            check(f"{sub['cname']} A", a_of(sub["cname"]), expected_a)
        check("unknown.pms-lab.test A", a_of("unknown.pms-lab.test"), "NXDOMAIN")
        check("example.com A (no forwarding)", a_of("example.com"), "NXDOMAIN")
    finally:
        server.stop()

    print("\nSELFTEST", "PASSED" if failures == 0 else f"FAILED ({failures} failures)")
    return 0 if failures == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Local lab DNS server")
    parser.add_argument("--selftest", action="store_true", help="verify records and exit")
    args = parser.parse_args()

    if args.selftest:
        sys.exit(selftest())

    server = start_server()
    print(f"Lab DNS server running on {lab_config.DNS_HOST}:{lab_config.DNS_PORT} (UDP). Ctrl+C to stop.")
    try:
        while server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
