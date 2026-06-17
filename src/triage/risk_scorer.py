"""
Per-process risk scoring engine.

Scoring weights
---------------
  +40  malfind hit (executable memory in process VAD)
  +20  suspicious parent (e.g. cmd.exe spawned from winword.exe)
  +15  known-bad path (process image in TEMP / AppData / unusual location)
  +15  unusual network (unexpected outbound connection for this process)
  +10  per IOC match

Whitelist bonus
---------------
  Legitimate Windows processes score is halved if the process name is on the
  whitelist.

Verdict thresholds
------------------
  < 30  → Clean
  30–69 → Suspicious
  >= 70 → Compromised
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WHITELIST = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "dwm.exe",
    "spoolsv.exe",
}

# Processes that should not normally have direct Internet connections
UNEXPECTED_NET_PROCS = {
    "lsass.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "svchost.exe",
    "winlogon.exe",
}

# Known-bad path fragments (case-insensitive)
BAD_PATHS = [
    "\\appdata\\local\\temp",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\recycle",
    "\\windows\\temp",
    "%temp%",
    "%appdata%",
]

# Suspicious parent→child relationships: {child: [bad_parents]}
SUSPICIOUS_PARENTS = {
    "cmd.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"],
    "powershell.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "mshta.exe"],
    "wscript.exe": ["winword.exe", "excel.exe", "powerpnt.exe"],
    "cscript.exe": ["winword.exe", "excel.exe", "powerpnt.exe"],
    "mshta.exe": ["winword.exe", "excel.exe", "powerpnt.exe"],
    "certutil.exe": ["cmd.exe", "powershell.exe"],
    "regsvr32.exe": ["cmd.exe", "powershell.exe", "winword.exe"],
    "rundll32.exe": ["winword.exe", "excel.exe", "powerpnt.exe"],
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ci(s) -> str:
    return str(s).lower() if s else ""


def _collect_processes(plugin_results: dict) -> list[dict]:
    """
    Build a unified process list from pslist rows.
    Falls back to psscan if pslist is empty.
    """
    rows = plugin_results.get("pslist", {}).get("rows", [])
    if not rows:
        rows = plugin_results.get("psscan", {}).get("rows", [])

    # Deduplicate by PID
    seen: set[str] = set()
    procs: list[dict] = []
    for row in rows:
        pid = str(row.get("PID") or row.get("UniqueProcessId") or "")
        if pid and pid not in seen:
            seen.add(pid)
            procs.append(row)
    return procs


def _malfind_pids(plugin_results: dict) -> set[str]:
    pids: set[str] = set()
    for row in plugin_results.get("malfind", {}).get("rows", []):
        pid = str(row.get("PID") or row.get("Pid") or "")
        if pid:
            pids.add(pid)
    return pids


def _net_pids(plugin_results: dict) -> set[str]:
    """PIDs with outbound network connections."""
    pids: set[str] = set()
    for plugin in ("netscan", "netstat"):
        for row in plugin_results.get(plugin, {}).get("rows", []):
            pid = str(row.get("PID") or row.get("Pid") or "")
            state = _ci(row.get("State") or "")
            foreign = row.get("ForeignAddr") or row.get("ForeignAddress") or ""
            # Skip loopback / 0.0.0.0 entries
            if pid and ("established" in state or not state) and foreign and \
               not foreign.startswith("0.0.0.0") and not foreign.startswith("127."):
                pids.add(pid)
    return pids


def _pid_to_name_map(procs: list[dict]) -> dict[str, str]:
    return {
        str(p.get("PID") or p.get("UniqueProcessId") or ""): _ci(
            p.get("ImageFileName") or p.get("Name") or ""
        )
        for p in procs
    }


def _ioc_pids(ioc_matches: list[dict]) -> dict[str, int]:
    """Returns {pid: hit_count}."""
    counts: dict[str, int] = {}
    for m in ioc_matches:
        pid = m.get("process_pid") or ""
        if pid:
            counts[pid] = counts.get(pid, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_processes(plugin_results: dict, ioc_matches: list[dict]) -> list[dict]:
    """
    Score each process and return a list sorted by risk_score descending.

    Each element:
    {
        "pid": str,
        "name": str,
        "ppid": str,
        "path": str,
        "risk_score": int,          # 0–100 (capped)
        "verdict": str,             # "Clean" | "Suspicious" | "Compromised"
        "risk_factors": list[str],  # human-readable reasons
    }
    """
    procs = _collect_processes(plugin_results)
    malfind_pids = _malfind_pids(plugin_results)
    net_pids = _net_pids(plugin_results)
    ioc_counts = _ioc_pids(ioc_matches)
    pid_name = _pid_to_name_map(procs)

    scored: list[dict] = []

    for proc in procs:
        pid = str(proc.get("PID") or proc.get("UniqueProcessId") or "")
        name_raw = proc.get("ImageFileName") or proc.get("Name") or ""
        name = _ci(name_raw)
        ppid = str(proc.get("PPID") or proc.get("InheritedFromUniqueProcessId") or "")
        path = str(proc.get("ImagePathName") or proc.get("Path") or "")

        score = 0
        factors: list[str] = []

        # 1. Malfind hit
        if pid in malfind_pids:
            score += 40
            factors.append("malfind: executable private memory (PAGE_EXECUTE_READWRITE)")

        # 2. Suspicious parent
        parent_name = pid_name.get(ppid, "")
        bad_parents_for = SUSPICIOUS_PARENTS.get(name, [])
        if parent_name and any(_ci(bp) == parent_name for bp in bad_parents_for):
            score += 20
            factors.append(f"suspicious parent: {name} spawned by {parent_name}")

        # 3. Known-bad path
        if path:
            path_lower = _ci(path)
            for bp in BAD_PATHS:
                if bp.lower() in path_lower:
                    score += 15
                    factors.append(f"suspicious image path: {path}")
                    break

        # 4. Unusual network
        if pid in net_pids and name in UNEXPECTED_NET_PROCS:
            score += 15
            factors.append(f"unexpected outbound connection for {name}")

        # 5. IOC matches
        hit_count = ioc_counts.get(pid, 0)
        if hit_count:
            score += 10 * hit_count
            factors.append(f"IOC database match ({hit_count} hit{'s' if hit_count > 1 else ''})")

        # Whitelist reduction (halve score for known-good system processes)
        if name in WHITELIST and score > 0:
            score = score // 2
            factors.append("(score halved: process is on legitimate Windows whitelist)")

        # Cap at 100
        score = min(score, 100)

        # Verdict
        if score < 30:
            verdict = "Clean"
        elif score < 70:
            verdict = "Suspicious"
        else:
            verdict = "Compromised"

        scored.append(
            {
                "pid": pid,
                "name": name_raw,
                "ppid": ppid,
                "path": path,
                "risk_score": score,
                "verdict": verdict,
                "risk_factors": factors,
            }
        )

    scored.sort(key=lambda p: p["risk_score"], reverse=True)
    return scored


def overall_verdict(scored_processes: list[dict]) -> tuple[str, int]:
    """
    Return (verdict_str, overall_score) derived from the highest-scoring process.
    """
    if not scored_processes:
        return "Clean", 0
    top = scored_processes[0]
    return top["verdict"], top["risk_score"]
