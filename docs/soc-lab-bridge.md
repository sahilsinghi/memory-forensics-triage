# SOC Lab Bridge

This guide bridges the memory-forensics-triage tool with Sahil's
[Network Segmentation Lab](~/Desktop/network-segmentation-lab) and the
Windows 11 SOC lab VM running in UTM on macOS.

## Prerequisites

- UTM installed with a Windows 11 VM (SOC lab)
- `atomic-red-team` PowerShell module installed in the Windows 11 VM
- `.venv` set up in this project (`pip install -e .`)

---

## Step 1 — Simulate an Attack with Atomic Red Team

Boot your Windows 11 SOC lab VM in UTM. Open PowerShell as Administrator:

```powershell
# Install Atomic Red Team if not already done
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# T1059.001 — PowerShell execution (simulates Cobalt Strike beacon)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# T1055 — Process Injection (triggers malfind hits)
Invoke-AtomicTest T1055 -TestNumbers 1

# T1071.001 — Web Protocols C2 (generates network artefacts)
Invoke-AtomicTest T1071.001 -TestNumbers 1

# T1547.001 — Registry Run Keys (persistence)
Invoke-AtomicTest T1547.001 -TestNumbers 1

# T1049 — System Network Connections Discovery
Invoke-AtomicTest T1049 -TestNumbers 1
```

Wait ~30 seconds for the artefacts to stabilise in memory.

---

## Step 2 — Take a Memory Snapshot via UTM

### Method A: UTM GUI (macOS)
1. In UTM, with the Windows VM running, go to **Virtual Machine → Capture Memory…**
2. Save as `win11_soc_lab_$(date +%Y%m%d_%H%M%S).vmdk`

### Method B: UTM CLI (Headless)
```bash
# Find the VM UUID
utmctl list

# Capture memory
utmctl capture-memory <VM_UUID> --output ~/Desktop/memory-forensics-triage/examples/soc-lab-generated/win11_$(date +%Y%m%d_%H%M%S).vmdk
```

---

## Step 3 — Convert to RAW Format

UTM produces VMDK snapshots. Convert to raw binary using `qemu-img`:

```bash
brew install qemu  # if not already installed

cd ~/Desktop/memory-forensics-triage/examples/soc-lab-generated/

# Convert VMDK to RAW
qemu-img convert -f vmdk -O raw win11_<timestamp>.vmdk win11_<timestamp>.raw

# Verify
file win11_<timestamp>.raw
ls -lh win11_<timestamp>.raw
```

For VirtualBox VMs that produce `.vmsn` snapshots:
```bash
# VirtualBox snapshot to raw
VBoxManage internalcommands converttoraw win11.vmsn win11.raw
```

---

## Step 4 — Run Triage Tool

```bash
cd ~/Desktop/memory-forensics-triage

# Full analysis with HTML report
.venv/bin/triage \
  --dump examples/soc-lab-generated/win11_<timestamp>.raw \
  --output html \
  --out-dir reports/ \
  --verbose

# Open the report
open reports/triage_win11_*.html
```

---

## Step 5 — Interpret Results

The triage tool will:
- Flag the PowerShell process spawned by T1059.001 as Suspicious (suspicious parent relationship)
- Detect the injected process from T1055 via malfind (PAGE_EXECUTE_READWRITE VAD)
- Show the outbound connection from T1071.001 in the Network Connections table
- Highlight the Run key from T1547.001 in the suspect process risk factors

Cross-reference the HTML report findings with:
- Your Suricata NIDS logs from the segmentation lab
- Windows Event Log 4688 (Process Creation) events
- Sysmon EventID 1 (ProcessCreate) if Sysmon is configured

---

## MITRE ATT&CK Coverage

| ATT&CK Technique | Detection Method |
|---|---|
| T1059.001 — PowerShell | Suspicious parent (pslist) |
| T1055 — Process Injection | malfind VAD analysis |
| T1071.001 — Web Protocol C2 | netscan foreign IPs vs IOC DB |
| T1547.001 — Registry Run Keys | svcscan / handles vs IOC DB |
| T1049 — Net Discovery | cmdline args in cmdline plugin |
| T1003.001 — LSASS Dump | malfind on lsass.exe (whitelisted but flagged) |

---

## Cleanup

After testing, clean up Atomic Red Team artefacts:
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1055 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

Note: Raw memory dump files are excluded from git via `.gitignore` (`*.raw`).
