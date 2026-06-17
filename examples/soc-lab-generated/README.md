# SOC Lab Generated Memory Dumps

Memory dumps generated from the Windows 11 SOC lab VM (UTM on macOS) are NOT
committed to this repository. They are typically multi-GB files.

## Generating a Dump

See the full walkthrough in `docs/soc-lab-bridge.md`.

Quick summary:
1. Run Atomic Red Team simulations in the Windows 11 VM
2. Take a UTM memory snapshot
3. Convert to RAW format with `qemu-img`
4. Run `triage` against the RAW file

## Naming Convention

Name generated dumps with this pattern for traceability:
```
win11_<YYYYMMDD>_<HHMM>_<technique>.raw
```

Examples:
```
win11_20260617_1430_T1059.raw    # PowerShell execution test
win11_20260617_1500_T1055.raw    # Process injection test
win11_20260617_1530_baseline.raw # Clean baseline before any simulation
```

## Expected File Sizes

| VM Configuration | Dump Size |
|---|---|
| 4 GB RAM VM | ~4 GB raw |
| 8 GB RAM VM | ~8 GB raw |
| With compression (zlib) | ~1-2 GB |

Volatility 3 can read compressed LIME format dumps if your capture tool supports it.

## Storage

Recommended: store dumps on an external SSD or Time Machine excluded folder:
```bash
# Exclude from Time Machine
tmutil addexclusion ~/Desktop/memory-forensics-triage/examples/soc-lab-generated/
```

The `.gitignore` already excludes `*.raw`, `*.vmem`, `*.mem`, `*.dmp` files.
