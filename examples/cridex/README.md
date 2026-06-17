# Cridex Memory Dump — Public Sample

Cridex is a banking trojan / worm from 2012 and the canonical sample used in
"The Art of Memory Forensics" and most Volatility 2-era tutorials. The dump is
a Windows XP SP2 image (~200MB).

**All original hosting is dead as of June 2026:**

| URL | Status |
|---|---|
| `files.sempersecurus.org/dumps/cridex_memdump.zip` | 403 Forbidden |
| `github.com/volatilityfoundation/volatility` release 2.4 | 404 Not Found |
| `archive.org/download/volatility-samples/cridex.vmem` | 503 Unavailable |

The best working alternative is the official Volatility Foundation Windows XP
test image below.

---

## Download — Official Volatility 3 Windows XP Sample

**Source**: https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1
**File**: `win-xp-laptop-2005-06-25.img.gz`
**Size**: 180 MB compressed
**HTTP status**: 200 OK (verified June 2026)

```bash
cd examples/cridex/

curl -L -o win-xp-2005.img.gz \
  "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-xp-laptop-2005-06-25.img.gz"

gunzip win-xp-2005.img.gz
ls -lh win-xp-2005.img
```

Run triage:

```bash
cd ~/Desktop/memory-forensics-triage

.venv/bin/python -m triage.cli \
  --dump examples/cridex/win-xp-2005.img \
  --output html \
  --out-dir reports/cridex/

open reports/cridex/triage_win-xp-2005_*.html
```

> **Note**: Volatility 3 has limited Windows XP support. Plugins like `netscan`
> and `mutantscan` may fail on XP — the tool handles this gracefully and
> continues with the remaining plugins. Use `--verbose` to see per-plugin errors.

---

## About Cridex

Cridex (aka Feodo) was a banking information-stealer that spread via mapped
network drives. It is the textbook example for process injection and network
C2 forensics in memory analysis courses.

**Forensic artifacts visible in memory dumps of infected XP systems:**

- `reader_sl.exe` (Adobe Reader Speed Launcher) injected by Cridex — shows
  up clean in pslist but malfind reveals `PAGE_EXECUTE_READWRITE` region
- `explorer.exe` with an injected code region (hollow injection pattern)
- Active TCP connections to C2 servers on port 8080 in netscan output
- Mutex `_AVIRA_2109` — Cridex checks for Avira AV before proceeding
- `psscan` finds more processes than `pslist` — demonstrates DKOM rootkit
  technique hiding processes from the active process list

**Why `psscan` vs `pslist` discrepancy matters**: pslist walks the
`EPROCESS.ActiveProcessLinks` doubly-linked list, which rootkits can unlink.
psscan scans raw memory for `EPROCESS` pool tags, bypassing the list entirely.
A discrepancy between the two is a strong rootkit indicator — one of the most
interview-relevant forensic concepts from this sample.

---

## Original Dump Hashes (if you have a private copy)

```
MD5:    d998b79e4e17e62c8a4b41f9a1c59306
SHA256: 5b136147911b041f0126ce82dfd24c4e2c79553b65d3240ecea2dcab4452dcb5
Size:   ~200 MB
OS:     Windows XP SP2 x86
Source: Volatility Foundation / "The Art of Memory Forensics" companion data
```

Place it at `examples/cridex/cridex.vmem` and run:

```bash
.venv/bin/python -m triage.cli \
  --dump examples/cridex/cridex.vmem \
  --output html \
  --out-dir reports/cridex/
```
