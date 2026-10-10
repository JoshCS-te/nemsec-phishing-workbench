# Branding

Save the NEMSEC logo here as **`nemsec-logo.png`** (square, transparent background, at least 256×256).

- UI: `scripts\setup.ps1` copies it to `frontend\public\nemsec-logo.png`; the rail shows it automatically (a letter mark is shown until it exists).
- PDF: `backend/app/reports/pdf.py` reads it from this folder (override with `PHB_LOGO_PATH`) and places it in the page header.

Brand name and URL used in the UI and reports: **NEMSEC**, **nemsec.com.ng**.
