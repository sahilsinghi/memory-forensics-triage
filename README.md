# Memory Forensics Triage Tool

[![CI](https://github.com/sahilsinghi/memory-forensics-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/sahilsinghi/memory-forensics-triage/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Volatility 3](https://img.shields.io/badge/volatility-3.x-green.svg)](https://github.com/volatilityfoundation/volatility3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automated memory forensics triage tool that wraps **Volatility 3**, runs **12
plugins in parallel**, scans output against a **500-indicator IOC database**
covering 10 APT/ransomware actors, and generates a polished **HTML triage report**.

Designed as a portfolio project bridging **memory forensics**, **threat
intelligence**, and **SOC operations** — complementing the
[Network Segmentation Lab](../network-segmentation-lab/) and
[APT Profiler](../apt-threat-actor-profiler/) projects.

---

## Quick Demo

```
================================================================
  Memory Forensics Triage Tool  |  Volatility 3
================================================================
  Dump      : /path/to/win11_20260617_1430.raw
  Format    : HTML
  IOC DB    : data/iocs/ (10 actors, 500 indicators)
  Profile   : auto-detect
================================================================

[1/5] Validating memory dump …
  OK — OS profile detected: Windows10x64_19041

[2/5] Running 12 Volatility 3 plugins in parallel (max 6 workers) …
  Done — 11/12 plugins succeeded, 1 errors, total 47.3s

[3/5] Scanning output against IOC database …
  Done — 3 IOC match(es) found

[4/5] Scoring process risk …
  Done — 89 processes scored

[5/5] Generating report …

================================================================
  VERDICT: COMPROMISED  (overall risk score: 85/100)
  Top suspect: malware.exe (PID 1234) — 85/100
  Report     : reports/triage_win11_20260617_143012.html
================================================================
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/sahilsinghi/memory-forensics-triage.git
cd memory-forensics-triage

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate     # Windows

# Install with dev dependencies
pip install -e ".[dev]"
```

---

## Usage

### Basic (HTML report)
```bash
triage --dump /path/to/memory.raw
```

### JSON report (for SIEM ingestion)
```bash
triage --dump memory.raw --output json --out-dir /tmp/reports/
```

### Custom IOC database
```bash
triage --dump memory.raw --ioc-db /my/custom/iocs/ --verbose
```

### With OS profile hint (faster detection)
```bash
triage --dump memory.raw --profile Win10x64_19041
```

### All options
```
Options:
  -d, --dump PATH          Path to memory dump file [required]
  -o, --output [html|json] Report format [default: html]
  --ioc-db PATH            IOC YAML directory [default: data/iocs/]
  --out-dir PATH           Output directory [default: .]
  --profile TEXT           Volatility OS profile hint
  -v, --verbose            Enable debug logging
  --help                   Show this message and exit
```

---

## IOC Database

The tool ships with **~500 indicators** across **10 threat actor profiles**:

| Actor | Type | Key TTPs |
|---|---|---|
| LockBit 3.0 | Ransomware | Global\\{BEF7C86E...} mutex, StealBit exfil |
| Conti | Ransomware | TrickBot/BazarLoader, Cobalt Strike |
| APT29 (Cozy Bear) | Espionage | SUNBURST, WellMess, MiniDuke |
| Lazarus Group | DPRK | ThreatNeedle, HOPLIGHT, Maui ransomware |
| FIN7 | eCrime | BOOSTWRITE, Lizar RAT, POS scraper |
| APT41 | Dual-use | PlugX, ShadowPad, Winnti rootkit |
| Carbanak | Banking | ATM monitoring, SWIFT targeting |
| Turla | Espionage | Snake rootkit, ComRAT, LightNeuron |
| Equation Group | NSA-linked | DoublePulsar, EternalBlue, GrayFish |
| DarkSide | Ransomware | Colonial Pipeline TTPs, rclone exfil |

Indicator types: `process_name`, `mutex`, `network_ip`, `file_path`, `registry_key`

---

## Risk Scoring Model

| Signal | Points |
|---|---|
| Malfind hit (RWX private memory) | +40 |
| Suspicious parent process | +20 |
| Process in TEMP/AppData/unusual path | +15 |
| Unexpected outbound network connection | +15 |
| IOC database match | +10 per hit |
| Legitimate Windows process (whitelist) | score ÷ 2 |

**Verdicts**: Clean < 30 | Suspicious 30-69 | Compromised ≥ 70

---

## Project Structure

```
memory-forensics-triage/
├── src/triage/
│   ├── cli.py          # Click CLI entry point
│   ├── validator.py    # Dump validation + OS detection
│   ├── orchestrator.py # Parallel plugin execution
│   ├── ioc_scanner.py  # IOC matching engine
│   ├── risk_scorer.py  # Per-process risk scoring
│   ├── report_html.py  # Jinja2 HTML report generator
│   ├── report_json.py  # JSON report for SIEM ingestion
│   ├── audit_log.py    # Structured JSONL audit logging
│   └── plugins/        # 12 Volatility 3 plugin wrappers
├── data/iocs/          # 10 threat actor YAML files
├── templates/          # report.html.j2 (Tailwind CSS)
├── tests/              # pytest suite (no real dump needed)
├── docs/               # Architecture, IOC database guide
└── examples/           # Stuxnet, Cridex download instructions
```

---

## Running Tests

```bash
# Full test suite (no memory dump needed — all mocked)
.venv/bin/pytest tests/ -v

# Specific test file
.venv/bin/pytest tests/test_ioc_scanner.py -v

# With coverage
.venv/bin/pytest tests/ --cov=triage --cov-report=term-missing
```

---

## Cross-Portfolio Bridge — SOC Detection Lab

This tool is designed to complement Sahil's
**[Network Segmentation Lab](../network-segmentation-lab/)** project:

1. Run Atomic Red Team simulations on the SOC lab Windows VM
2. Trigger malfind-visible injections (T1055) and network C2 (T1071)
3. Take a UTM memory snapshot and convert to RAW
4. Run `triage` to detect artefacts across all 12 memory plugins
5. Cross-correlate with Suricata NIDS alerts from the segmentation lab

Full walkthrough: `docs/soc-lab-bridge.md`

---

## Adding New IOCs

```bash
# Add to an existing actor file
vim data/iocs/lockbit.yml

# Or create a new actor
cp data/iocs/lockbit.yml data/iocs/newactor.yml
```

See `docs/adding-new-iocs.md` for the full schema and quality checklist.

---

## Definition of Done

- [x] 12 Volatility 3 plugin wrappers (pslist, psscan, pstree, malfind, netscan, netstat, cmdline, handles, dlllist, modscan, mutantscan, svcscan)
- [x] Concurrent plugin execution via ThreadPoolExecutor (max 6 workers)
- [x] Graceful error handling — plugin failure doesn't stop triage
- [x] IOC database with 10 actors (~500 indicators) from public reports
- [x] Risk scorer with 5 weighted signals and process whitelist
- [x] Polished HTML report (Tailwind CSS, colour-coded verdict banner)
- [x] JSON report for SIEM ingestion
- [x] Structured JSONL audit log
- [x] pytest suite passing without a real memory dump
- [x] CLI with `--dump`, `--output`, `--ioc-db`, `--out-dir`, `--profile`, `--verbose`
- [x] Architecture documentation with Mermaid diagram
- [x] SOC Lab bridge documentation
- [x] Public sample download instructions (Stuxnet, Cridex)
- [x] GitHub Actions CI workflow

---

## Sample Run Output

```
================================================================
  VERDICT: COMPROMISED  (overall risk score: 85/100)
  Top suspect: malware.exe (PID 1234) — 85/100
  Report     : reports/triage_win11_20260617_143012.html
================================================================

Suspect Process Breakdown (top 5):
  malware.exe  PID 1234  Score: 85  COMPROMISED
    - malfind: executable private memory (PAGE_EXECUTE_READWRITE)
    - IOC database match (3 hits): LockBit C2 IP, LockBit mutex
    - suspicious image path: C:\Users\Public\malware.exe

  cmd.exe      PID 5678  Score: 30  SUSPICIOUS
    - suspicious parent: cmd.exe spawned by malware.exe

  lsass.exe    PID 888   Score: 0   CLEAN
    - (no flags)

IOC Matches:
  185.220.101.45  network_ip  LockBit  CRITICAL  netscan  malware.exe (1234)
  Global\{BEF7C86E-...}  mutex  LockBit  CRITICAL  mutantscan
  lockbit.exe  process_name  LockBit  CRITICAL  pslist  (not found)
```
