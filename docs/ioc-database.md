# IOC Database

## Overview

The IOC database lives in `data/iocs/` and consists of YAML files — one per threat
actor. The tool ships with 10 actor files containing ~500 total indicators sourced
from public APT reports, CISA advisories, and vendor threat intelligence.

## YAML Schema

```yaml
actor: "ActorName"            # Human-readable name shown in reports
description: "..."            # Optional free-text description
references:                   # Optional list of source URLs
  - "https://..."
indicators:
  - type: process_name        # Indicator type (see below)
    value: "lockbit.exe"      # The indicator value to match
    severity: critical        # critical | high | medium | low
    citation: "https://..."   # Source for this specific IOC
    description: "..."        # What this indicator means
```

## Indicator Types

| Type | Description | Matched Against |
|---|---|---|
| `process_name` | Process executable name | pslist, psscan `ImageFileName` |
| `mutex` | Windows mutex name | mutantscan `Name` (substring) |
| `network_ip` | IP address (no port) | netscan, netstat `ForeignAddr` |
| `file_path` | File/DLL path fragment | dlllist, handles `Path` (substring) |
| `registry_key` | Registry key path fragment | svcscan, handles `Name` (substring) |

## Matching Logic

- `process_name`: case-insensitive equality check on the process image name
- `mutex`: case-insensitive substring search in the mutex name string
- `network_ip`: exact match on the foreign IP (port stripped before comparison)
- `file_path`: case-insensitive substring search in path fields
- `registry_key`: case-insensitive substring search in key name fields

## Bundled Actor Files

| File | Actor | Indicators |
|---|---|---|
| `lockbit.yml` | LockBit 2.0/3.0 | ~50 |
| `conti.yml` | Conti / TrickBot | ~50 |
| `apt29.yml` | APT29 / Cozy Bear / NOBELIUM | ~50 |
| `lazarus.yml` | Lazarus / HIDDEN COBRA | ~50 |
| `fin7.yml` | FIN7 / Carbon Spider | ~50 |
| `apt41.yml` | APT41 / Double Dragon | ~50 |
| `carbanak.yml` | Carbanak banking trojan | ~50 |
| `turla.yml` | Turla / Snake / Uroburos | ~50 |
| `equation_group.yml` | Equation Group (NSA) | ~50 |
| `darkside.yml` | DarkSide / Colonial Pipeline | ~50 |

## Adding New IOCs

See `docs/adding-new-iocs.md` for a step-by-step guide.

## Severity Guidelines

- **critical**: Active exploitation / primary payload — immediate response required
- **high**: Strong indicator of compromise — likely malicious
- **medium**: Suspicious but could have legitimate use — investigate further
- **low**: Weak signal / tool that could be dual-use

## Citation Policy

Every indicator must have a `citation` field referencing a public source:
- CISA advisories (`.gov` URLs)
- Vendor threat intelligence blogs (Mandiant, CrowdStrike, Kaspersky, etc.)
- Malpedia entries (`malpedia.caad.fkie.fraunhofer.de`)
- Public malware databases (`any.run`, `VirusTotal`)

Do not add indicators based solely on private or commercial threat intelligence
feeds without appropriate licensing.
