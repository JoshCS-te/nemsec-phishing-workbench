import re

from app.parsing.sanitize import sanitize_html

from .conftest import sample

HOSTILE = """<html><head><meta http-equiv="refresh" content="0;url=http://x.invalid"><link rel=stylesheet href="http://css.invalid/a.css">
<style>body{background:url(http://bg.invalid/a.png)}</style><script>fetch('http://x.invalid')</script><base href="http://base.invalid/"></head>
<body onload="steal()"><img src="http://tracker.invalid/p.gif"><img src="cid:logo@x"><img srcset="http://s.invalid/a.png 2x">
<svg><script>alert(1)</script></svg><iframe src="http://f.invalid"></iframe><object data="http://o.invalid"></object><embed src="x.swf">
<form action="http://collect.invalid"><input name=p></form><a href="https://real.example" onclick="x()">click</a>
<div style="background-image:url('http://bg2.invalid/x.png')">bg</div><video poster="http://v.invalid/p.png"></video>
<a href="javascript:alert(1)">js</a></body></html>"""


def test_sanitizer_removes_active_and_remote_content():
    out = sanitize_html(HOSTILE)["html"]
    low = out.lower()
    for bad in ("<script", "onload", "onclick", "<iframe", "<object", "<embed", "<form", "<input", "<meta", "<link",
                "<base", "<svg", "<style", "<video", "srcset"):
        assert bad not in low, bad
    assert not re.search(r"\b(src|href|action|poster|background)\s*=\s*[\"']?(https?:)?//", low)
    assert "url(" not in low
    assert not re.search(r"\shref=", low)  # no clickable links at all


def test_links_shown_but_not_clickable():
    out = sanitize_html('<a href="http://evil.invalid/x">https://bank.example</a>')["html"]
    assert 'data-dest="http://evil.invalid/x"' in out
    assert "href=" not in out


def test_remote_images_replaced_with_placeholder():
    r = sanitize_html('<img src="http://t.invalid/p.gif" alt="logo">')
    assert "image blocked" in r["html"] and "t.invalid" not in r["html"]
    assert r["removed"]["remote_resource_references"] >= 1


def test_preview_endpoint_sends_restrictive_csp(client):
    ev = client.post("/api/emails/import", files={"file": ("03.eml", sample("03_misleading_link.eml"), "message/rfc822")}).json()
    r = client.get(f"/api/emails/{ev['evidence_id']}/preview?mode=html")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "sandbox" in csp and "form-action 'none'" in csp
    assert "script-src" not in csp  # falls back to default-src 'none'
    assert r.headers["x-content-type-options"] == "nosniff"
    body = r.text.lower()
    assert "<script" not in body and "tracker.invalid" not in body and "<form" not in body
    text = client.get(f"/api/emails/{ev['evidence_id']}/preview?mode=text")
    assert "<a " not in text.text  # text view is escaped


def test_lookalike_host_shown_in_punycode():
    out = sanitize_html('<a href="https://cоntoso.example/help">https://contoso.example/help</a>')["html"]
    assert "xn--" in out and "non-ASCII host" in out
