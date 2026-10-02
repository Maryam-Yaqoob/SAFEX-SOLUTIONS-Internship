"""
lab_http_server.py - Mock web server for the Subdomain Takeover lab.

AUTHORIZED LAB ONLY. Listens on 127.0.0.1:8080 and picks a mock page based on
the HTTP Host header, using the http_profile of each subdomain in lab_config.py.
It never makes outbound requests.

Usage:
    python lab_http_server.py             # run the server (Ctrl+C to stop)
    python lab_http_server.py --selftest  # start, verify every profile, exit

ASSUMPTIONS (flagged):
  * TCP port 8080 on 127.0.0.1 is free on this machine.
  * The provider error pages below are simplified mocks written for this lab,
    modelled on the publicly documented "unclaimed resource" messages.
  * The "claimed_patched" page deliberately CONTAINS an unclaimed-site error
    phrase inside normal content. It is a false-positive trap: a naive
    substring check would flag it, a tuned check (Stage 6) must not.
"""

import argparse
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import lab_config

HEALTHY_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>PMS Tenant Portal</title></head>
<body>
<h1>PMS Tenant Portal</h1>
<p>Welcome to the Property Management tenant portal (lab demo).</p>
<ul><li>Available listings</li><li>Submit a maintenance request</li><li>Pay rent</li></ul>
</body></html>
"""

S3_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error><Code>NoSuchBucket</Code>"
    "<Message>The specified bucket does not exist</Message>"
    "<BucketName>pms-blog-old</BucketName>"
    "<RequestId>LAB0000000000001</RequestId><HostId>lab-mock</HostId></Error>\n"
)

CLAIMED_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>PMS Tenant Resources</title></head>
<body>
<h1>PMS Tenant Resources</h1>
<p>Move-in guides, lease FAQs and building rules for tenants.</p>
<h2>Security notes for our IT team</h2>
<p>When a hosted site is deleted, visitors may see an error such as
<code>There isn't a GitHub Pages site here.</code> Remove the matching DNS
record when that happens.</p>
</body></html>
"""

GENERIC_404_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>
"""

UNKNOWN_HOST_TEXT = "Lab: no site configured for this Host\n"

# profile -> (status, content-type, Server header, body)
PROFILES = {
    "healthy_app": (200, "text/html; charset=utf-8", "nginx", HEALTHY_HTML),
    "s3_nosuchbucket": (404, "application/xml", "AmazonS3", S3_XML),
    "claimed_patched": (200, "text/html; charset=utf-8", "GitHub.com", CLAIMED_HTML),
    "generic_404": (404, "text/html; charset=utf-8", "nginx", GENERIC_404_HTML),
}
UNKNOWN_PROFILE = (404, "text/plain; charset=utf-8", "LabServer", UNKNOWN_HOST_TEXT)


def profile_for_host(host_header):
    """Map a Host header (with optional :port) to a profile tuple."""
    host = (host_header or "").split(":")[0].strip().lower()
    for sub in lab_config.SUBDOMAINS:
        if sub["name"] == host:
            return PROFILES.get(sub["http_profile"], UNKNOWN_PROFILE)
    return UNKNOWN_PROFILE


class LabHandler(BaseHTTPRequestHandler):
    def version_string(self):
        return getattr(self, "_server_header", "LabServer")

    def _respond(self, send_body):
        status, ctype, server, body = profile_for_host(self.headers.get("Host"))
        data = body.encode("utf-8")
        self._server_header = server
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def do_GET(self):
        self._respond(True)

    def do_HEAD(self):
        self._respond(False)

    def log_message(self, fmt, *args):
        print(f"[lab-http] {self.headers.get('Host')} {fmt % args}")


def start_server():
    server = ThreadingHTTPServer((lab_config.HTTP_HOST, lab_config.HTTP_PORT), LabHandler)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def selftest():
    """Request every lab host and check status, Server header and body marker."""
    import requests

    # host -> (status, Server header, must-contain marker)
    cases = {
        "portal.pms-lab.test": (200, "nginx", "PMS Tenant Portal"),
        "blog.pms-lab.test": (404, "AmazonS3", "NoSuchBucket"),
        "tenant.pms-lab.test": (200, "GitHub.com", "There isn't a GitHub Pages site here"),
        "legacy.pms-lab.test": (404, "nginx", "The requested URL was not found"),
        "docs.pms-lab.test": (404, "LabServer", "no site configured"),
    }
    failures = 0
    server = start_server()
    time.sleep(0.3)
    try:
        for host, (status, srv, marker) in cases.items():
            url = f"http://{lab_config.HTTP_HOST}:{lab_config.HTTP_PORT}/"
            resp = requests.get(url, headers={"Host": host}, timeout=3)
            ok = (
                resp.status_code == status
                and resp.headers.get("Server") == srv
                and marker in resp.text
            )
            failures += 0 if ok else 1
            print(
                f"[{'PASS' if ok else 'FAIL'}] {host}: status={resp.status_code} "
                f"server={resp.headers.get('Server')!r} marker_found={marker in resp.text}"
            )
    finally:
        server.shutdown()
        server.server_close()

    print("\nSELFTEST", "PASSED" if failures == 0 else f"FAILED ({failures} failures)")
    return 0 if failures == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Local lab HTTP server")
    parser.add_argument("--selftest", action="store_true", help="verify profiles and exit")
    args = parser.parse_args()

    if args.selftest:
        sys.exit(selftest())

    server = start_server()
    print(f"Lab HTTP server running on http://{lab_config.HTTP_HOST}:{lab_config.HTTP_PORT} (Ctrl+C to stop).")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
