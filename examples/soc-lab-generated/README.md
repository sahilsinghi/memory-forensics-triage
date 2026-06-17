# SOC Lab Generated Memory Dumps

Memory dumps generated from the Windows 11 SOC lab VM are NOT committed to
this repository — they are typically 4–8 GB files. This README covers the
end-to-end workflow: simulate an attack → capture memory → run triage.

Full step-by-step walkthrough: [`docs/soc-lab-bridge.md`](../../docs/soc-lab-bridge.md)
SOC Detection Lab repo: [github.com/sahilsinghi/soc-detection-lab](https://github.com/sahilsinghi/soc-detection-lab)

---

## Prerequisites

- UTM running a Windows 11 VM (the SOC lab)
- `invoke-atomicredteam` PowerShell module installed in the VM
- This tool set up: `pip install -e .` in the project root

---

## Quick Start (3 commands)

```bash
# 1. Capture memory from the running UTM VM (see Step 2 below for full options)
utmctl capture-memory <VM_UUID> --output examples/soc-lab-generated/win11_$(date +%Y%m%d_%H%M).vmdk

# 2. Convert VMDK snapshot to raw binary
qemu-img convert -f vmdk -O raw \
  examples/soc-lab-generated/win11_$(date +%Y%m%d_%H%M).vmdk \
  examples/soc-lab-generated/win11_$(date +%Y%m%d_%H%M).raw

# 3. Run triage
.venv/bin/python -m triage.cli \
  --dump examples/soc-lab-generated/win11_$(date +%Y%m%d_%H%M).raw \
  --output html \
  --out-dir reports/soc-lab/
```

---

## Recommended Attack Sequences + Expected Triage Output

Run these in PowerShell (Administrator) inside the Windows 11 VM before
capturing memory. Each combination produces a different verdict.

### Scenario A — Process Injection (Compromised verdict)

```powershell
Invoke-AtomicTest T1055 -TestNumbers 1   # Process injection → malfind hit
Invoke-AtomicTest T1059.001 -TestNumbers 1  # PowerShell beacon → suspicious parent
```

**Expected triage output:**
| Finding | Source plugin | Risk contribution |
|---|---|---|
| Injected process with RWX memory | `malfind` | +40 pts |
| PowerShell spawned from unusual parent | `pslist` / `pstree` | +20 pts |
| **Verdict: COMPROMISED (60+)** | | |

### Scenario B — C2 Beacon + Registry Persistence (Suspicious verdict)

```powershell
Invoke-AtomicTest T1071.001 -TestNumbers 1  # HTTP C2 beacon
Invoke-AtomicTest T1547.001 -TestNumbers 1  # Registry Run key persistence
```

**Expected triage output:**
| Finding | Source plugin | Risk contribution |
|---|---|---|
| Outbound connection to unusual foreign IP | `netscan` | +15 pts |
| Run key path in handles/svcscan output | `svcscan` | +15 pts |
| **Verdict: SUSPICIOUS (30–70)** | | |

### Scenario C — Baseline (Clean verdict)

No Atomic Red Team techniques — capture immediately after VM boot.

**Expected triage output:** Clean verdict (<30), standard Windows processes
only, no malfind hits, no IOC matches. Useful for validating the tool does not
false-positive on a healthy system.

---

## File Naming Convention

```
win11_<YYYYMMDD>_<HHMM>_<technique>.raw
```

Examples:
```
win11_20260617_1430_T1055.raw       # Process injection
win11_20260617_1500_T1059.raw       # PowerShell execution
win11_20260617_1530_T1055_T1059.raw # Combined scenario
win11_20260617_1600_baseline.raw    # Clean baseline
```

---

## Expected Runtimes

Based on the live run against the 2 GB official Volatility Foundation test dump
(12/12 plugins succeeded, 172 seconds):

| VM RAM | Dump size | Expected runtime |
|---|---|---|
| 4 GB | ~4 GB | ~5–6 min |
| 8 GB | ~8 GB | ~10–12 min |
| 2 GB (test) | ~2 GB | ~3 min |

The 60-second target in the README applies to smaller SOC lab dumps (512 MB–1 GB).
For larger dumps, runtime scales roughly linearly with dump size.

---

## Storage Notes

Raw memory dump files are excluded from git via `.gitignore` (`*.raw`, `*.vmem`,
`*.dmp`, `*.mem`). Store dumps on an external SSD or exclude from Time Machine:

```bash
tmutil addexclusion ~/Desktop/memory-forensics-triage/examples/soc-lab-generated/
```

---

## Cleanup

After capturing and analysing, clean up Atomic Red Team artefacts in the VM:

```powershell
Invoke-AtomicTest T1055 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1071.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```
