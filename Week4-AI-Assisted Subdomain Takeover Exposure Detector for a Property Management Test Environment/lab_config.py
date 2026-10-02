"""
lab_config.py - Shared configuration for the local Subdomain Takeover lab.

AUTHORIZED LAB ONLY: everything here lives on 127.0.0.1. The fake zone
"pms-lab.test" uses the reserved ".test" TLD (RFC 6761), so it can never
resolve on the real internet. Provider-looking CNAME targets such as
"pms-docs-old.github.io" are answered ONLY by our local DNS server; the
real GitHub / AWS / Heroku are never contacted.

ASSUMPTIONS (flagged):
  1. All lab names resolve to 127.0.0.1; a single HTTP server (port 8080)
     will virtual-host by the Host header, so no hosts-file edits are needed.
  2. The "expected" verdicts below are the ground truth used for true/false
     positive testing in the later stages. They are our own lab design.
"""

LAB_DOMAIN = "pms-lab.test"
LAB_IP = "127.0.0.1"

DNS_HOST = "127.0.0.1"
DNS_PORT = 5353          # non-privileged port, works on Windows without admin
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8080

# Each entry describes one subdomain of the fake Property Management app.
#   cname            : provider-looking CNAME target (None = plain A record)
#   target_resolves  : False -> CNAME target has no DNS record (NXDOMAIN, dangling)
#   http_profile     : which mock page the lab HTTP server returns (Stage 2, part 2)
#   expected         : ground-truth verdict for testing the scanner later
SUBDOMAINS = [
    {
        "name": "portal.pms-lab.test",
        "cname": None,
        "target_resolves": True,
        "http_profile": "healthy_app",
        "expected": "NOT_VULNERABLE",
        "description": "Healthy tenant portal (plain A record, no third-party CNAME).",
        # ASSUMPTION (lab design, not real-world data): sensitivity/cookie_scope
        # simulate real-world context for Stage 5 severity scoring only.
        "sensitivity": "high",
        "cookie_scope": "parent",
    },
    {
        "name": "docs.pms-lab.test",
        "cname": "pms-docs-old.azurewebsites.net",
        "target_resolves": False,
        "http_profile": "none",
        "expected": "CONFIRMED",
        "description": "Dangling CNAME: Azure App Service target no longer exists (NXDOMAIN).",
        "sensitivity": "low",
        "cookie_scope": "host-only",
    },
    {
        "name": "blog.pms-lab.test",
        "cname": "pms-blog-old.s3.amazonaws.com",
        "target_resolves": True,
        "http_profile": "s3_nosuchbucket",
        "expected": "CONFIRMED",
        "description": "CNAME resolves but page shows the unclaimed-bucket error signature.",
        "sensitivity": "low",
        "cookie_scope": "host-only",
    },
    {
        "name": "tenant.pms-lab.test",
        "cname": "pms-tenant.github.io",
        "target_resolves": True,
        "http_profile": "claimed_patched",
        "expected": "NOT_VULNERABLE",
        "description": "Third-party CNAME that is properly claimed and serving content (false-positive check).",
        "sensitivity": "high",
        "cookie_scope": "parent",
    },
    {
        "name": "legacy.pms-lab.test",
        "cname": "pms-legacy.herokuapp.com",
        "target_resolves": True,
        "http_profile": "generic_404",
        "expected": "AMBIGUOUS",
        "description": "Provider CNAME with a generic 404; needs LLM-assisted interpretation.",
        "sensitivity": "medium",
        "cookie_scope": "host-only",
    },
]


def target_names():
    """Return the list of lab subdomain names."""
    return [s["name"] for s in SUBDOMAINS]
