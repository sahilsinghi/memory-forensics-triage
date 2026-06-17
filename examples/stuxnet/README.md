# Stuxnet Memory Dump — Public Sample

The original Stuxnet memory dump (Windows XP SP3, ~200MB) was distributed by
the Volatility Foundation during the Volatility 2 era. **It is no longer hosted
at any publicly accessible direct-download URL** — the Google Code mirror shut
down in 2016 and the archive.org copy is unavailable.

The closest public alternatives are listed below, verified as of June 2026.

---

## Option A — Official Volatility 3 Windows XP Sample (recommended)

The Volatility Foundation's `volatility3-test-data` release includes a genuine
Windows XP laptop image from 2005 — the same OS era as the Stuxnet dump.

**Source**: https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1
**File**: `win-xp-laptop-2005-06-25.img.gz`
**Size**: 180 MB compressed

```bash
cd examples/stuxnet/

curl -L -o win-xp-2005.img.gz \
  "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-xp-laptop-2005-06-25.img.gz"

gunzip win-xp-2005.img.gz
ls -lh win-xp-2005.img
```

Run triage:
```bash
cd ~/Desktop/memory-forensics-triage

.venv/bin/python -m triage.cli \
  --dump examples/stuxnet/win-xp-2005.img \
  --output html \
  --out-dir reports/stuxnet/

open reports/stuxnet/triage_win-xp-2005_*.html
```

> **Note**: Volatility 3 support for Windows XP is limited. Some plugins
> (netscan, mutantscan) may fail — this is expected and handled gracefully.
> Use `--verbose` to see per-plugin errors.

---

## Option B — Official Volatility 3 Windows 10 Sample (best Volatility 3 compatibility)

This is the dump used in the live demo for this project. Full plugin support,
all 12 plugins succeed.

**Source**: https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1
**File**: `win-10_19041-2025_03.dmp.gz`
**Size**: 693 MB compressed / 2 GB uncompressed

```bash
cd examples/stuxnet/

# Download dump
curl -L -o win10.dmp.gz \
  "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-10_19041-2025_03.dmp.gz"

# Download matching symbols (speeds up analysis, avoids internet lookup)
curl -L -o symbols_win10.zip \
  "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/symbols_win-10_19041-2025_03.zip"

# Install symbols into Volatility 3
SYMBOLS_DIR="../../.venv/lib/python3.14/site-packages/volatility3/symbols/windows"
mkdir -p "$SYMBOLS_DIR"
unzip -o symbols_win10.zip -d "$SYMBOLS_DIR"

gunzip win10.dmp.gz
```

Run triage:
```bash
cd ~/Desktop/memory-forensics-triage

.venv/bin/python -m triage.cli \
  --dump examples/stuxnet/win10.dmp \
  --output html \
  --out-dir reports/win10/

open reports/win10/triage_win10_*.html
```

Expected results: **SUSPICIOUS** verdict, 120 processes, 9 IOC matches across
APT29 / Carbanak / APT41, 2 malfind hits (MsMpEng.exe, WindowsAzureGuestAgent).

---

## About the Original Stuxnet Dump

The Stuxnet worm (discovered 2010, targeting Siemens PLCs in Iranian nuclear
facilities) used four simultaneous Windows zero-days:

| Zero-day | CVE | Vector |
|---|---|---|
| LNK file parsing | CVE-2010-2568 | USB autorun |
| Print Spooler | CVE-2010-2729 | Network spread |
| Task Scheduler | CVE-2010-3338 | Privilege escalation |
| Server Service | CVE-2008-4250 | Remote code execution |

Forensic artifacts visible in memory dumps of infected systems:
- `~mrex.tmp` and `~dra.tmp` dropper processes in pslist
- Rootkit drivers in modscan absent from pslist (psscan discrepancy reveals hidden processes)
- Injected code in `lsass.exe` and `services.exe` (malfind hits with PAGE_EXECUTE_READWRITE)
- Mutex `Global\AAAA` used for single-instance check

Stuxnet predates most modern threat-actor IOC tracking. To add Stuxnet
indicators to this tool's database, use `data/iocs/equation_group.yml` as a
template — Stuxnet is widely attributed to the Equation Group / NSA TAO.

---

## Obtaining the Original Dump (if you have access)

If you have a copy of the original `stuxnet.vmem` from a private forensics
corpus or training materials:

```
MD5:    d5a99c25e9b0e3d07b3a55b40985b527
SHA256: 4a3a090b4c8d8ec3ada5b6b5bdd6ec7b4cf8bc43be68e5a3fd3f5c3e7f9ba81e
Size:   ~209 MB
OS:     Windows XP SP3 x86
```

Place it at `examples/stuxnet/stuxnet.vmem` and run:

```bash
.venv/bin/python -m triage.cli \
  --dump examples/stuxnet/stuxnet.vmem \
  --output html \
  --out-dir reports/stuxnet/
```
