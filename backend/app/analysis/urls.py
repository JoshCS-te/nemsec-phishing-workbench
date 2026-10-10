"""URL extraction and explainable URL indicators.

Nothing here makes a network request. URLs are parsed as strings only;
no DNS lookups, no redirect expansion, no fetching.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote, urlsplit

TEXT_URL_RE = re.compile(
    r"""(?ix)
    \b(
      (?:https?|hxxps?|ftp|file|javascript|data|mailto):[^\s<>"'\]\)]+
      | www\.[^\s<>"'\]\)]+
    )""",
)
URLISH_TEXT_RE = re.compile(r"(?i)^\s*(?:(?:https?|ftp)://)?(?:www\.)?([a-z0-9¡-￿-]+(?:\.[a-z0-9¡-￿-]+)+)(?:[:/?#][^\s]*)?\s*$")
COMMON_SCHEMES = {"http", "https", "mailto"}
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "ms-office", "ms-word", "ms-excel", "search-ms", "ms-msdt"}
# Second-level public suffixes we know about. Not a full Public Suffix List — see docs/limitations.md.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "com.au", "net.au",
    "org.au", "co.za", "co.jp", "co.in", "com.br", "com.cn", "co.ke", "com.gh", "co.nz",
}
CONFUSABLE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}


@dataclass
class ExtractedUrl:
    source: str
    original: str
    visible_text: str | None = None
    warnings: list[dict[str, str]] = field(default_factory=list)
    scheme: str | None = None
    hostname: str | None = None
    normalized_host: str | None = None
    unicode_host: str | None = None
    parse_ok: bool = True

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []  # (source, url, text)
        self._stack: list[list[Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and "href" in a:
            self._stack.append([a["href"], []])
            if tag == "area":
                self.links.append(("html_href", a["href"], a.get("alt", "")))
                self._stack.pop()
        elif tag == "form" and a.get("action"):
            self.links.append(("html_form_action", a["action"], ""))
        elif tag in ("img", "script", "iframe", "embed", "source") and a.get("src"):
            self.links.append(("html_resource", a["src"], a.get("alt", "")))
        elif tag == "link" and a.get("href"):
            self.links.append(("html_resource", a["href"], ""))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.links.append(("html_meta_refresh", m.group(1).strip(), ""))

    def handle_data(self, data: str) -> None:
        for item in self._stack:
            item[1].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._stack:
            href, parts = self._stack.pop()
            self.links.append(("html_href", href, re.sub(r"\s+", " ", "".join(parts)).strip()))

    def close(self) -> None:
        super().close()
        while self._stack:  # unclosed <a>
            href, parts = self._stack.pop()
            self.links.append(("html_href", href, re.sub(r"\s+", " ", "".join(parts)).strip()))


def registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.rstrip(".").lower()
    if _as_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _as_ip(host: str) -> str | None:
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    # Decimal / hex / octal integer hosts (http://3232235777/, http://0xC0A80101/)
    try:
        if re.fullmatch(r"0x[0-9a-f]+|\d+", h, re.I):
            n = int(h, 0) if h.lower().startswith("0x") else int(h)
            if 0 <= n <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(n))
        parts = h.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|\d+", p, re.I) for p in parts):
            nums = [int(p, 16) if p.lower().startswith("0x") else (int(p, 8) if p.startswith("0") and len(p) > 1 else int(p)) for p in parts]
            if all(0 <= x <= 255 for x in nums):
                return ".".join(map(str, nums))
    except ValueError:
        return None
    return None


def _scripts_in(label: str) -> set[str]:
    scripts = set()
    for ch in label:
        if ch.isascii():
            if ch.isalpha():
                scripts.add("LATIN")
            continue
        try:
            scripts.add(unicodedata.name(ch).split(" ")[0])
        except ValueError:
            scripts.add("UNKNOWN")
    return scripts


def _w(code: str, message: str, weight: str = "context") -> dict[str, str]:
    return {"code": code, "message": message, "weight": weight}


def analyse_url(original: str, source: str, visible_text: str | None = None) -> ExtractedUrl:
    u = ExtractedUrl(source=source, original=original, visible_text=visible_text or None)
    candidate = original.strip()
    if candidate != original:
        u.warnings.append(_w("whitespace", "URL has leading/trailing whitespace in the source."))
    defanged = False
    if re.match(r"(?i)hxxps?:", candidate):
        defanged = True
        candidate = re.sub(r"(?i)^hxxp", "http", candidate)
        u.warnings.append(_w("defanged", "URL is written in defanged form (hxxp). It was probably pasted from a report, not a live link."))
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
        u.warnings.append(_w("schemeless", "Link written without a scheme; parsed as http:// for analysis only."))

    if re.search(r"[\s\x00-\x1f]", candidate):
        u.warnings.append(_w("malformed_whitespace", "URL contains whitespace or control characters.", "notable"))
    try:
        parts = urlsplit(candidate)
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError as exc:
        u.parse_ok = False
        u.warnings.append(_w("malformed", f"URL could not be parsed: {exc}", "notable"))
        return u

    scheme = (parts.scheme or "").lower() or None
    u.scheme = scheme
    if scheme is None:
        u.warnings.append(_w("relative", "No scheme: relative link or fragment. Destination depends on context."))
    elif scheme in DANGEROUS_SCHEMES:
        u.warnings.append(_w("dangerous_scheme", f"'{scheme}:' links can run code, embed content or open local resources rather than a web page.", "notable"))
    elif scheme not in COMMON_SCHEMES and scheme not in ("ftp", "tel", "cid"):
        u.warnings.append(_w("unusual_scheme", f"Unusual scheme '{scheme}:' (expected http, https or mailto)."))

    if scheme in ("http", "https", "ftp") and not parts.hostname:
        u.parse_ok = False
        u.warnings.append(_w("malformed_no_host", "Web URL has no hostname.", "notable"))

    if parts.username is not None or parts.password is not None:
        shown_user = unquote(parts.username or "")
        msg = f"URL contains user-info before '@' ('{shown_user}'). Browsers go to the host after '@', so the text before it can make a link look like another site."
        if parts.password is not None:
            msg += " A password component is also present (not displayed)."
        u.warnings.append(_w("embedded_credentials", msg, "notable"))

    if scheme == "mailto":
        addr = parts.path.split("?")[0]
        u.hostname = addr.rsplit("@", 1)[1].lower() if "@" in addr else None
        u.normalized_host = u.hostname
        return u

    host = parts.hostname
    if host:
        u.hostname = host
        norm = host.rstrip(".").lower()
        ip = _as_ip(norm)
        if ip:
            u.normalized_host = ip
            obfuscated = ip != norm.strip("[]")
            u.warnings.append(_w("ip_host",
                                 f"Destination is an IP address ({ip}){' written in an obfuscated numeric form' if obfuscated else ''}, not a domain name. "
                                 "Legitimate services sometimes do this (devices, internal tools), but it hides who operates the site.",
                                 "notable"))
            try:
                ipobj = ipaddress.ip_address(ip)
                if ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local:
                    u.warnings.append(_w("private_ip", f"{ip} is a private/loopback/link-local address."))
            except ValueError:
                pass
        else:
            unicode_host = None
            ascii_host = norm
            if any(ord(c) > 127 for c in norm):
                try:
                    ascii_host = norm.encode("idna").decode("ascii")
                except UnicodeError:
                    u.warnings.append(_w("idn_invalid", "Internationalised hostname cannot be IDNA-encoded.", "notable"))
                unicode_host = norm
            elif "xn--" in norm:
                try:
                    unicode_host = norm.encode("ascii").decode("idna")
                except UnicodeError:
                    u.warnings.append(_w("idn_invalid", "Punycode label could not be decoded.", "notable"))
            u.normalized_host = ascii_host
            u.unicode_host = unicode_host
            if unicode_host:
                mixed = []
                for label in unicode_host.split("."):
                    scripts = _scripts_in(label) - {"DIGIT", "HYPHEN-MINUS"}
                    if len(scripts) > 1:
                        mixed.append(f"{label} ({', '.join(sorted(scripts))})")
                confusable = sorted(_scripts_in(unicode_host) & CONFUSABLE_SCRIPTS)
                msg = f"Internationalised domain: shown as '{unicode_host}', registered as '{ascii_host}'."
                weight = "context"
                if mixed:
                    msg += f" Labels mixing scripts: {'; '.join(mixed)} — a common look-alike technique."
                    weight = "notable"
                elif confusable:
                    msg += f" Uses {', '.join(confusable)} characters, some of which look identical to Latin letters."
                    weight = "notable"
                u.warnings.append(_w("idn", msg, weight))
        if parts.port and parts.port not in (80, 443):
            u.warnings.append(_w("nonstandard_port", f"Non-standard port {parts.port}."))
        if norm.count(".") >= 5:
            u.warnings.append(_w("many_subdomains", "Hostname has many labels; the real domain is the rightmost part, not the first."))

    if "%" in (parts.netloc or ""):
        u.warnings.append(_w("encoded_host", "Percent-encoding in the host part.", "notable"))
    if defanged:
        pass

    # Link text vs destination
    if visible_text and u.normalized_host:
        m = URLISH_TEXT_RE.match(visible_text)
        if m:
            shown_host = m.group(1).lower().rstrip(".")
            try:
                shown_ascii = shown_host.encode("idna").decode("ascii") if any(ord(c) > 127 for c in shown_host) else shown_host
            except UnicodeError:
                shown_ascii = shown_host
            if registrable_domain(shown_ascii) != registrable_domain(u.normalized_host):
                u.warnings.append(_w(
                    "text_destination_mismatch",
                    f"Visible text shows '{shown_host}' but the link goes to '{u.normalized_host}'.",
                    "notable",
                ))
    return u


def extract_urls(text_bodies: list[str], html_bodies: list[str]) -> list[ExtractedUrl]:
    found: list[ExtractedUrl] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, url: str, text: str | None) -> None:
        key = (source, url, text or "")
        if key in seen:
            return
        seen.add(key)
        found.append(analyse_url(url, source, text))

    for body in html_bodies:
        collector = _LinkCollector()
        try:
            collector.feed(body)
            collector.close()
        except Exception:  # HTMLParser is lenient; guard anyway
            pass
        for source, url, text in collector.links:
            add(source, url, text)
    for body in text_bodies:
        for m in TEXT_URL_RE.finditer(body):
            url = m.group(1).rstrip(".,;:!?")
            add("text_body", url, None)
    return found
