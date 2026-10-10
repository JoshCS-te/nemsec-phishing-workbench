"""Browser end-to-end walkthrough: upload -> review -> notes -> sandbox (demo) -> report -> reviewed PDF.

Prerequisites: backend running with PHB_SANDBOX_MODE=demo and a worker (or PHB_INLINE_WORKER=1),
frontend running on http://127.0.0.1:3000, and `pip install playwright && python -m playwright install chromium`.

    python frontend/e2e/ui_flow.py [--shots DIR] [--chromium PATH]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

REPO = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:3000"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default=None)
    ap.add_argument("--chromium", default=None)
    args = ap.parse_args()
    shots = Path(args.shots) if args.shots else None

    def snap(page, name):
        if shots:
            page.screenshot(path=str(shots / f"flow-{name}.png"), full_page=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chromium) if args.chromium else p.chromium.launch()
        page = browser.new_page(viewport={"width": 1400, "height": 1000}, accept_downloads=True)
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        # 1. create a case
        page.goto(BASE + "/")
        page.get_by_label("Title").fill("UI flow: fake invoice")
        page.get_by_role("button", name="Create case").click()
        page.wait_for_url(re.compile(r"/cases/CASE-"))
        case_url = page.url

        # 2. import an email into it
        page.get_by_role("link", name="Import email into case").click()
        page.locator("input[type=file]").set_input_files(str(REPO / "samples" / "emails" / "04_misleading_extension.eml"))
        expect(page.locator(".badge", has_text=re.compile("Imported|Already imported"))).to_be_visible(timeout=15000)
        snap(page, "1-import")

        # 3. review a finding
        page.goto(case_url + "?tab=findings")
        card = page.locator("details.finding", has_text="File extension does not match content")
        expect(card).to_be_visible(timeout=20000)
        card.locator("summary").click()
        card.get_by_role("button", name="Mark relevant").click()
        expect(card.locator(".badge", has_text="Relevant")).to_be_visible()
        card.get_by_label("Analyst comment").fill("PE executable disguised as a PDF invoice.")
        card.get_by_role("button", name="Save comment").click()
        snap(page, "2-findings")

        # 4. notes
        page.get_by_role("tab", name=re.compile("Notes")).click()
        page.get_by_label("Note", exact=True).fill("Recipient confirmed they did not open the attachment.")
        page.get_by_role("button", name="Add note").click()
        expect(page.get_by_text("Recipient confirmed they did not open the attachment.")).to_be_visible()
        page.get_by_role("radio", name=re.compile("Unanswered question")).check()
        page.get_by_label("Note", exact=True).fill("Did the same sender target other departments?")
        page.get_by_role("button", name="Add note").click()
        expect(page.get_by_text("Did the same sender target other departments?")).to_be_visible()

        # 5. sandbox (demo) on the attachment
        page.get_by_role("tab", name=re.compile("Evidence")).click()
        page.get_by_role("link", name="Invoice_INV-2026-1043.pdf").click()
        page.get_by_label("Your name (recorded in the audit trail)").fill("J. Analyst")
        submit = page.get_by_role("button", name=re.compile("Run demo submission|Execute in sandbox"))
        expect(submit).to_be_disabled()  # explicit confirmation required
        page.get_by_role("checkbox", name=re.compile("I want to execute")).check()
        submit.click()
        page.locator("a[href^='/sandbox/jobs/']").first.click()
        expect(page.locator(".badge", has_text="Verified")).to_be_visible(timeout=60000)
        expect(page.get_by_text(re.compile("DEMO")).first).to_be_visible()
        snap(page, "3-sandbox-job")

        # 6. report
        page.goto(case_url + "/report")
        page.get_by_role("button", name="Create draft report").click()
        page.get_by_label("Case summary").fill("Invoice-themed email carrying a Windows executable named as a PDF.")
        page.get_by_role("combobox", name=re.compile("^Assessment")).select_option("likely_malicious")
        page.get_by_label("Why you reached this assessment").fill("Content is a PE file behind a .pdf name; sandbox run was DEMO only.")
        page.get_by_role("button", name="Save draft").click()
        expect(page.get_by_text("Draft saved.")).to_be_visible()
        with page.expect_download() as dl:
            page.get_by_role("link", name=re.compile("Export PDF")).click()
        draft_pdf = dl.value
        assert "DRAFT" in draft_pdf.suggested_filename, draft_pdf.suggested_filename
        page.get_by_label("Reviewer name").fill("Lead Reviewer")
        page.get_by_role("button", name="Mark reviewed").click()
        expect(page.get_by_text(re.compile("Reviewed by Lead Reviewer"))).to_be_visible()
        snap(page, "4-report")
        with page.expect_download() as dl:
            page.get_by_role("link", name=re.compile("Export PDF")).click()
        final = dl.value
        assert "reviewed" in final.suggested_filename, final.suggested_filename
        if shots:
            final.save_as(str(shots / final.suggested_filename))
        browser.close()
        if errors:
            print("Page errors:", *errors, sep="\n  ")
            return 1
    print("UI flow passed:", final.suggested_filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())
