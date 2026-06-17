# Adding New IOCs

This guide explains how to contribute new indicators to the database.

## Quick Start

1. Identify the threat actor for your indicator
2. Open (or create) the corresponding YAML file in `data/iocs/`
3. Add your indicator following the schema below
4. Run the test suite to confirm it integrates correctly

```bash
.venv/bin/pytest tests/test_ioc_scanner.py -v
```

---

## Schema Reference

```yaml
actor: "ActorName"
description: "Brief actor description"
references:
  - "https://public-source-for-entire-file"
indicators:
  - type: process_name        # Required — see types below
    value: "evil.exe"         # Required — the exact indicator value
    severity: critical         # Required — critical|high|medium|low
    citation: "https://..."   # Required — public source URL
    description: "What this indicator means for the analyst"
```

## Indicator Types

### `process_name`
Match against the process image name in pslist/psscan output.
- Use the exact executable name (e.g. `"lockbit.exe"`, `"malware.dll"`)
- Case-insensitive comparison is applied automatically
- Do not include path components — use `file_path` for path-based matching

```yaml
- type: process_name
  value: "evildll.exe"
  severity: critical
  citation: "https://example-report.com/analysis"
  description: "Primary dropper payload for ExampleGroup"
```

### `mutex`
Match against mutantscan output using substring search.
- Include the full mutex name if known
- Partial GUID matches are supported (e.g. `"BEF7C86E"` matches `"Global\\{BEF7C86E-...}"`)

```yaml
- type: mutex
  value: "Global\\{BEF7C86E-11D7-6B75-D7A0-7D6E4DA89768}"
  severity: critical
  citation: "https://cisa.gov/lockbit-advisory"
  description: "LockBit 3.0 primary execution mutex"
```

### `network_ip`
Match against the foreign IP address in netscan/netstat output.
- Use the bare IP address (no port, no CIDR)
- Only IPv4 addresses are supported currently
- Do not add CDN or cloud provider IPs (too many false positives)

```yaml
- type: network_ip
  value: "185.220.101.45"
  severity: critical
  citation: "https://cisa.gov/lockbit-advisory"
  description: "Known C2 — confirmed Tor exit node"
```

### `file_path`
Match against file paths in dlllist/handles output using substring search.
- Use forward or backward slashes (matching is case-insensitive substring)
- Good for detecting artefacts in unusual directories

```yaml
- type: file_path
  value: "\\AppData\\Roaming\\LockBit"
  severity: high
  citation: "https://example.com"
  description: "LockBit staging directory"
```

### `registry_key`
Match against registry key names in svcscan/handles output.
- Use the full key path for specificity
- Substring matching reduces false positives for long key names

```yaml
- type: registry_key
  value: "HKCU\\Software\\LockBit3"
  severity: critical
  citation: "https://example.com"
  description: "LockBit 3.0 configuration stored in registry"
```

---

## Creating a New Actor File

If the threat actor does not have an existing file:

```bash
cp data/iocs/lockbit.yml data/iocs/newactor.yml
```

Edit the file to set the correct `actor` name, `description`, and `references`.
Replace all indicators with your new ones.

---

## Quality Checklist

Before submitting indicators, verify:

- [ ] Every indicator has a `citation` pointing to a public source
- [ ] Severity is appropriate (critical = immediate compromise evidence)
- [ ] No internal/private IPs in `network_ip` entries
- [ ] No overly broad `file_path` values that would match legitimate software
- [ ] Process names do not match common legitimate tools without context
- [ ] Tests pass: `.venv/bin/pytest tests/ -v`

---

## Severity Guidelines

| Severity | When to Use | Example |
|---|---|---|
| `critical` | Direct evidence of the malware running or C2 | Primary payload, known C2 IP |
| `high` | Strong indicator with very few false positives | Known-bad mutex, staging path |
| `medium` | Suspicious but could be dual-use | Admin tool abused by this actor |
| `low` | Weak signal, requires corroboration | Generic registry key name |

---

## Sources of Quality IOCs

- [CISA Advisories](https://www.cisa.gov/resources-tools/resources/ics-advisories)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- [ANY.RUN Malware Trends](https://any.run/malware-trends/)
- [Mandiant APT Profiles](https://www.mandiant.com/resources/insights/apt-groups)
- [CrowdStrike Adversary Intelligence](https://www.crowdstrike.com/blog/category/threat-intel-research/)
- [MITRE ATT&CK Software](https://attack.mitre.org/software/)
