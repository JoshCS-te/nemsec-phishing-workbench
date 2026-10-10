/*
 * NEMSEC sandbox verification program — HARMLESS.
 *
 * What it does, and nothing else:
 *   1. Writes one small text file named NEMSEC_SANDBOX_DEMO_<pid>.txt into %TEMP%.
 *   2. Exits with code 0.
 * No network access, no registry changes, no persistence, no child processes.
 * Purpose: give the sandbox an easily recognisable, safe behaviour to observe
 * ("file created in %TEMP%") so the end-to-end pipeline can be verified.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    char dir[MAX_PATH];
    char path[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, dir);
    if (n == 0 || n > MAX_PATH) return 1;
    snprintf(path, sizeof path, "%sNEMSEC_SANDBOX_DEMO_%lu.txt", dir, (unsigned long)GetCurrentProcessId());
    FILE *f = fopen(path, "w");
    if (!f) return 2;
    fputs("NEMSEC Phishing Investigation Workbench - harmless sandbox verification file.\r\n"
          "If you can read this, the sample ran inside the sandbox guest.\r\n", f);
    fclose(f);
    return 0;
}
