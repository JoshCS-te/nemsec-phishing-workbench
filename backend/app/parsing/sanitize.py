"""Sanitised HTML preview.

Layers of protection (each one is enough on its own for most attacks; together
they cover each other's gaps):

1. ``nh3`` (Rust ``ammonia``) allow-list sanitiser: no scripts, styles blocks,
   forms, iframes, objects, embeds, SVG, meta refresh, event handlers.
2. Post-processing: every ``href`` is removed and kept only as visible text
   (``data-dest`` + tooltip), so a click goes nowhere. Remote image sources are
   dropped and replaced by a visible placeholder.
3. The preview is served from the API with a CSP of ``default-src 'none';
   sandbox`` (no network, no script, unique origin) and ``nosniff``.
4. The UI loads it in ``<iframe sandbox="">`` (no scripts, no same-origin,
   no top navigation, no forms, no popups).
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

import nh3

ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col", "colgroup", "dd", "del", "div",
    "dl", "dt", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "li", "ol", "p",
    "pre", "s", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th",
    "thead", "tr", "tt", "u", "ul",
}
GENERIC_ATTRS = {"style", "align", "valign", "width", "height", "bgcolor", "color", "border", "cellpadding",
                 "cellspacing", "colspan", "rowspan", "dir", "lang", "title", "face", "size"}
ATTRIBUTES = {tag: set(GENERIC_ATTRS) for tag in ALLOWED_TAGS}
ATTRIBUTES["a"] |= {"href"}
ATTRIBUTES["img"] |= {"src", "alt"}

SAFE_STYLE_PROPS = {
    "color", "background-color", "font-weight", "font-style", "font-size", "font-family", "text-align",
    "text-decoration", "padding", "padding-left", "padding-right", "padding-top", "padding-bottom", "margin",
    "margin-left", "margin-right", "margin-top", "margin-bottom", "border", "border-collapse", "width", "height",
    "line-height", "vertical-align", "display", "max-width",
}
URL_SCHEMES = {"http", "https", "mailto", "ftp", "tel", "cid", "data", "file", "javascript", "vbscript", "ms-office"}

REMOTE_RESOURCE_RE = re.compile(
    r"""(?:src|background|href|poster|data|action|srcset)\s*=\s*["']?\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import""",
    re.I,
)
SCRIPT_RE = re.compile(r"<\s*script\b|\son[a-z]+\s*=|javascript:", re.I)


def _attribute_filter(tag: str, attr: str, value: str) -> str | None:
    if attr == "style":
        low = value.lower()
        if "url(" in low or "expression" in low or "@import" in low or "behavior" in low:
            return None
        return value
    if tag == "img" and attr == "src":
        v = value.strip().lower()
        if v.startswith("data:image/") and not v.startswith("data:image/svg"):
            return value
        return None  # remote, cid:, svg and anything else dropped
    if attr == "background":
        return None
    return value


_A_HREF_RE = re.compile(r'<a\b([^>]*?)\shref="([^"]*)"([^>]*)>', re.I)
_IMG_NO_SRC_RE = re.compile(r"<img\b(?![^>]*\bsrc=)([^>]*)>", re.I)


def _ascii_dest(dest_escaped: str) -> str:
    """Show internationalised hosts in punycode so look-alike characters can't hide in the preview."""
    raw = html.unescape(dest_escaped)
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return dest_escaped
    if host and any(ord(c) > 127 for c in host):
        try:
            puny = host.encode("idna").decode("ascii")
        except UnicodeError:
            puny = "invalid IDN"
        return dest_escaped + html.escape(f" [non-ASCII host, registered as {puny}]", quote=True)
    return dest_escaped


def _neutralise_links(clean: str) -> str:
    def repl(m: re.Match[str]) -> str:
        dest = _ascii_dest(m.group(2))
        return f'<a class="pb-link"{m.group(1)} data-dest="{dest}" title="Destination (not opened): {dest}"{m.group(3)}>'
    return _A_HREF_RE.sub(repl, clean)


def _placeholder_images(clean: str) -> str:
    def repl(m: re.Match[str]) -> str:
        alt = re.search(r'alt="([^"]*)"', m.group(1))
        label = f" alt: {alt.group(1)}" if alt and alt.group(1) else ""
        return f'<span class="pb-blocked" role="img" aria-label="Blocked image">[image blocked{label}]</span>'
    return _IMG_NO_SRC_RE.sub(repl, clean)


def sanitize_html(raw_html: str) -> dict:
    """Return sanitised body HTML plus a description of what was removed."""
    remote_count = len(REMOTE_RESOURCE_RE.findall(raw_html))
    script_count = len(SCRIPT_RE.findall(raw_html))
    form_count = len(re.findall(r"<\s*form\b", raw_html, re.I))
    frame_count = len(re.findall(r"<\s*(?:iframe|frame|object|embed|applet)\b", raw_html, re.I))
    meta_refresh = len(re.findall(r"<\s*meta[^>]+http-equiv\s*=\s*[\"']?refresh", raw_html, re.I))

    clean = nh3.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        clean_content_tags={"script", "style", "title", "noscript", "template", "textarea", "select", "object", "iframe", "svg", "math"},
        attributes=ATTRIBUTES,
        attribute_filter=_attribute_filter,
        url_schemes=URL_SCHEMES,
        strip_comments=True,
        link_rel=None,
        filter_style_properties=SAFE_STYLE_PROPS,
    )
    clean = _neutralise_links(clean)
    clean = _placeholder_images(clean)
    # Belt and braces: no href may survive post-processing.
    clean = re.sub(r"\shref\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", clean, flags=re.I)
    return {
        "html": clean,
        "removed": {
            "remote_resource_references": remote_count,
            "script_indicators": script_count,
            "forms": form_count,
            "frames_or_embeds": frame_count,
            "meta_refresh": meta_refresh,
        },
    }


PREVIEW_CSS = """
:root{color-scheme:light}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:16px;color:#1a1a1a;background:#fff;word-wrap:break-word}
a.pb-link{color:#0b57d0;text-decoration:underline dotted;cursor:not-allowed}
a.pb-link::after{content:" \\27E8" attr(data-dest) "\\27E9";font:12px ui-monospace,Consolas,monospace;color:#8a1c1c;background:#fff4e5;padding:0 3px;border-radius:3px;word-break:break-all}
.pb-blocked{display:inline-block;border:1px dashed #888;color:#555;background:#f3f3f3;font:12px ui-monospace,Consolas,monospace;padding:2px 6px;margin:2px}
img{max-width:100%}
table{max-width:100%}
"""

PREVIEW_CSP = (
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors {ancestors}; sandbox"
)


def preview_document(clean_body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        f"<style>{PREVIEW_CSS}</style></head><body>{clean_body}</body></html>"
    )


def text_preview_document(text: str) -> str:
    return preview_document(f"<pre style=\"white-space:pre-wrap;font:13px/1.5 ui-monospace,Consolas,monospace\">{html.escape(text)}</pre>")
