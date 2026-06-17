# Stuxnet Memory Dump — Public Sample

The Stuxnet memory dump from the Volatility Foundation's public corpus is NOT
committed to this repository to avoid large file bloat. Download it using the
instructions below.

## Source

The dump is hosted on the Volatility Foundation's public samples repository.
MD5: `d5a99c25e9b0e3d07b3a55b40985b527`
SHA256: `5f3aa2c44...` (see Volatility wiki for current hash)

Original URL: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

## Download

```bash
cd ~/Desktop/memory-forensics-triage/examples/stuxnet/

# Download via curl
curl -L -o stuxnet.vmem \
  "https://archive.org/download/malware-corpus-samples/stuxnet.vmem"

# Verify MD5
md5sum stuxnet.vmem
# Expected: d5a99c25e9b0e3d07b3a55b40985b527
```

## Running Triage

```bash
cd ~/Desktop/memory-forensics-triage

.venv/bin/triage \
  --dump examples/stuxnet/stuxnet.vmem \
  --output html \
  --out-dir reports/stuxnet/ \
  --verbose

open reports/stuxnet/triage_stuxnet_*.html
```

## What to Expect

The Stuxnet dump contains the Stuxnet worm (CVE-2010-2568 / LNK vulnerability).
Expected triage findings:
- `~mrex.tmp` dropper processes visible in pslist
- Rootkit driver entries in modscan (hidden from pslist — psscan discrepancy)
- Suspicious memory regions in system processes (malfind hits)
- Four zero-days used: LNK, Print Spooler, Task Scheduler, Server Service

Stuxnet indicators are not in the current IOC database (it predates most modern
threat actor tracking). You can add them using the `Equation Group` actor file
as a reference.

## Notes

- This dump was captured on a Windows XP SP3 system
- Volatility 3 may require `--profile Win32Bit` hint for best results
- Use `vol3 -f stuxnet.vmem windows.info` to confirm detected profile
