# Cridex Memory Dump — Public Sample

The Cridex banking trojan memory dump from the Volatility Foundation's public
corpus is NOT committed to this repository. Download it using the instructions below.

## Source

This is the canonical public Volatility tutorial memory dump, widely used in
forensics training and referenced in "The Art of Memory Forensics" textbook.

MD5: `d998b79e4e17e62c8a4b41f9a1c59306`

## Download

```bash
cd ~/Desktop/memory-forensics-triage/examples/cridex/

# Primary source — Volatility Foundation sample
curl -L -o cridex.vmem \
  "https://github.com/volatilityfoundation/volatility/releases/download/2.4/cridex.vmem.zip"

# Unzip
unzip cridex.vmem.zip && rm cridex.vmem.zip

# Verify
md5sum cridex.vmem
# Expected: d998b79e4e17e62c8a4b41f9a1c59306

# Alternative single-file download
curl -L -o cridex.vmem \
  "https://archive.org/download/volatility-samples/cridex.vmem"
```

## Running Triage

```bash
cd ~/Desktop/memory-forensics-triage

.venv/bin/triage \
  --dump examples/cridex/cridex.vmem \
  --output html \
  --out-dir reports/cridex/ \
  --verbose

open reports/cridex/triage_cridex_*.html
```

## What to Expect

Cridex is a banking information-stealing worm that spreads via network shares.
Expected triage findings:
- `reader_sl.exe` showing suspicious behaviour (Cridex injects into this)
- Network connections to Cridex C2 infrastructure
- `explorer.exe` with hollow injection (malfind hit expected)
- Mutex `_AVIRA_2109` — Cridex checks for Avira AV presence

The Cridex C2 IPs from the 2012 campaign are not in the current IOC database
(too old / burned infrastructure). This dump is best used for testing the
malfind and netscan detection logic rather than IOC matching.

## Notes

- Captured on Windows XP SP3 (32-bit)
- This is the sample used in "The Art of Memory Forensics" Chapter 12
- Volatility 3 automagic should auto-detect the profile
- Great for validating that `psscan` finds more processes than `pslist` (rootkit DKOM)
