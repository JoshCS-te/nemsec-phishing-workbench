from app.analysis.urls import analyse_url, extract_urls, registrable_domain


def codes(u):
    return {w["code"] for w in u.warnings}


def test_extract_from_text_and_html_with_visible_text():
    urls = extract_urls(["see https://a.example/x and www.b.example/y."],
                        ['<a href="http://evil.invalid/p">https://bank.example/login</a><form action="http://c.invalid/s"></form>'])
    by_orig = {u.original: u for u in urls}
    assert "https://a.example/x" in by_orig and "www.b.example/y" in by_orig
    a = by_orig["http://evil.invalid/p"]
    assert a.visible_text == "https://bank.example/login"
    assert "text_destination_mismatch" in codes(a)
    assert by_orig["http://c.invalid/s"].source == "html_form_action"


def test_matching_link_text_is_not_flagged():
    u = analyse_url("https://www.contoso.example/login", "html_href", "contoso.example")
    assert "text_destination_mismatch" not in codes(u)


def test_ip_destinations_including_obfuscated():
    assert "ip_host" in codes(analyse_url("http://192.0.2.45:8080/owa", "x"))
    dec = analyse_url("http://3221225985/", "x")  # 192.0.2.1 as a decimal integer
    assert "ip_host" in codes(dec) and dec.normalized_host == "192.0.2.1"
    hexed = analyse_url("http://0xC0000201/", "x")
    assert hexed.normalized_host == "192.0.2.1"


def test_idn_mixed_script_lookalike():
    u = analyse_url("https://cоntoso.example/help", "x")  # Cyrillic о
    assert u.normalized_host.startswith("xn--")
    idn = [w for w in u.warnings if w["code"] == "idn"][0]
    assert idn["weight"] == "notable" and "CYRILLIC" in idn["message"]


def test_punycode_input_is_decoded_for_display():
    u = analyse_url("https://xn--cntoso-demo-zfg.example/", "x")
    assert u.unicode_host and u.unicode_host != u.normalized_host


def test_schemes_credentials_and_malformed():
    assert "dangerous_scheme" in codes(analyse_url("javascript:alert(1)", "x"))
    assert "dangerous_scheme" in codes(analyse_url("data:text/html;base64,AAAA", "x"))
    assert "unusual_scheme" in codes(analyse_url("ms-settings:privacy", "x"))
    cred = analyse_url("https://bank.example@evil.invalid/login", "x")
    assert "embedded_credentials" in codes(cred) and cred.normalized_host == "evil.invalid"
    pw = analyse_url("ftp://user:secret@files.example/", "x")
    assert all("secret" not in w["message"] for w in pw.warnings)  # password never echoed
    bad = analyse_url("http://host.example:99999/", "x")
    assert not bad.parse_ok and "malformed" in codes(bad)


def test_original_string_preserved_exactly():
    original = "  hxxp://Evil.Invalid/Path?A=1  "
    u = analyse_url(original, "x")
    assert u.original == original
    assert u.normalized_host == "evil.invalid"
    assert {"defanged", "whitespace"} <= codes(u)


def test_registrable_domain_heuristic():
    assert registrable_domain("a.b.contoso.com.ng") == "contoso.com.ng"
    assert registrable_domain("mail.example.co.uk") == "example.co.uk"
    assert registrable_domain("x.y.example") == "y.example"
