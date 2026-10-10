# Harmless sandbox verification programs

| File | What it does | Nothing else |
|---|---|---|
| `nemsec_sandbox_demo.c` → `nemsec_sandbox_demo.exe` | Writes `%TEMP%\NEMSEC_SANDBOX_DEMO_<pid>.txt` containing a fixed sentence, exits 0 | no network, registry, persistence or child processes |
| `nemsec_sandbox_demo.bat` | Writes `%TEMP%\NEMSEC_SANDBOX_DEMO_BAT.txt`, exits 0 | same |

The `.exe` was built from the included source with:

```
python -m ziglang cc -target x86_64-windows-gnu -Os -s -o nemsec_sandbox_demo.exe nemsec_sandbox_demo.c
```

SHA-256 of the committed build: `640865af4702daf36ae2b132d892781cd0e2671db7723684eab73df594d1f8a2`. Rebuild it yourself if you prefer (any C compiler targeting Windows works; MSVC: `cl /O2 nemsec_sandbox_demo.c`).

It requires the Universal C Runtime, included with Windows 10 and later. Some antivirus products flag any unknown unsigned executable; that is expected for this file.
