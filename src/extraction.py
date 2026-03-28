"""Run Volatility 3 plugins on a memory dump and extract features for classification."""

import json
import os
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd

# Exact feature order expected by the model (must match X_train_filtered.csv)
FEATURE_ORDER = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads",
    "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc",
    "handles.ndesktop", "handles.nkey", "handles.nthread",
    "handles.ndirectory", "handles.nsemaphore", "handles.ntimer",
    "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "malfind.ninjections", "malfind.commitCharge", "malfind.protection",
    "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list", "psxview.not_in_csrss_handles",
    "psxview.not_in_session", "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg", "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg", "psxview.not_in_deskthrd_false_avg",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks",
]

# Features that require signed log1p transform before scaling (matches notebook 02)
LOG1P_FEATURES = [
    "handles.avg_handles_per_proc", "handles.nhandles", "handles.nsection",
    "malfind.commitCharge", "malfind.ninjections", "malfind.protection",
    "psxview.not_in_csrss_handles", "psxview.not_in_deskthrd",
    "psxview.not_in_ethread_pool",
    "svcscan.kernel_drivers", "svcscan.nservices",
]

# Volatility 3 plugin names
VOL3_PLUGINS = {
    "pslist": "windows.pslist",
    "dlllist": "windows.dlllist",
    "handles": "windows.handles",
    "ldrmodules": "windows.ldrmodules",
    "malfind": "windows.malfind",
    "psxview": "windows.psxview",
    "svcscan": "windows.svcscan",
    "callbacks": "windows.callbacks",
}

PLUGINS = list(VOL3_PLUGINS.keys())


def check_volatility(vol_path: str = None) -> str:
    """Verify Volatility 3 is installed and return the command path."""
    cmd = vol_path or os.environ.get("VOLATILITY_PATH", "vol")
    try:
        result = subprocess.run(
            [cmd, "-h"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and ("Volatility 3" in result.stdout
                                        or "volatility3" in result.stdout.lower()
                                        or "A volatility framework" in result.stdout):
            return cmd
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    raise RuntimeError(
        f"Volatility 3 not found at '{cmd}'. Install it or set VOLATILITY_PATH.\n"
        "Install with: pip install volatility3\n"
        "See: https://github.com/volatilityfoundation/volatility3"
    )


def run_plugin(dump_path: str, plugin: str,
               vol_path: str = "vol", timeout: int = 600) -> list:
    """Execute a single Volatility 3 plugin and return parsed JSON rows."""
    vol3_name = VOL3_PLUGINS[plugin]
    cmd = [vol_path, "-f", dump_path, "-r", "json", vol3_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise subprocess.SubprocessError(
            f"Plugin '{vol3_name}' failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    return _parse_json_output(result.stdout)


def _parse_json_output(stdout: str) -> list:
    """Parse Volatility 3 JSON renderer output into a flat list of row dicts."""
    data = json.loads(stdout)
    return _flatten_rows(data)


def _flatten_rows(data) -> list:
    """Flatten Vol3's potentially nested JSON output (handles __children trees)."""
    if isinstance(data, dict):
        data = data.get("data", [data])
    rows = []
    for item in data:
        if isinstance(item, dict):
            row = {k: v for k, v in item.items() if k != "__children"}
            rows.append(row)
            for child in item.get("__children", []):
                rows.extend(_flatten_rows([child]))
    return rows


# ---------------------------------------------------------------------------
# Parsers — each takes a list of row dicts (from Vol3 JSON) and returns
# a dict of feature values
# ---------------------------------------------------------------------------

def parse_pslist(rows: list) -> dict:
    """Parse pslist JSON rows for process counts and thread averages."""
    if not rows:
        return {"pslist.nproc": 0, "pslist.nppid": 0, "pslist.avg_threads": 0.0}

    pids = []
    ppids = []
    threads = []
    for row in rows:
        pid = row.get("PID")
        ppid = row.get("PPID")
        thds = row.get("Threads")
        if pid is not None:
            pids.append(pid)
        if ppid is not None:
            ppids.append(ppid)
        if thds is not None:
            threads.append(int(thds))

    return {
        "pslist.nproc": len(pids),
        "pslist.nppid": len(set(ppids)),
        "pslist.avg_threads": float(np.mean(threads)) if threads else 0.0,
    }


def parse_dlllist(rows: list) -> dict:
    """Parse dlllist JSON rows for average DLLs per process."""
    if not rows:
        return {"dlllist.avg_dlls_per_proc": 0.0}

    dlls_per_proc = {}
    for row in rows:
        pid = row.get("PID")
        if pid is not None:
            dlls_per_proc[pid] = dlls_per_proc.get(pid, 0) + 1

    avg = float(np.mean(list(dlls_per_proc.values()))) if dlls_per_proc else 0.0
    return {"dlllist.avg_dlls_per_proc": avg}


def parse_handles(rows: list) -> dict:
    """Parse handles JSON rows for counts by type."""
    type_counts = {
        "Desktop": 0, "Key": 0, "Thread": 0, "Directory": 0,
        "Semaphore": 0, "Timer": 0, "Section": 0, "Mutant": 0,
    }
    pids = set()
    total = 0

    for row in rows:
        total += 1
        pid = row.get("PID")
        if pid is not None:
            pids.add(pid)
        handle_type = str(row.get("Type", ""))
        if handle_type in type_counts:
            type_counts[handle_type] += 1

    n_procs = len(pids) if pids else 1
    return {
        "handles.nhandles": total,
        "handles.avg_handles_per_proc": total / n_procs,
        "handles.ndesktop": type_counts["Desktop"],
        "handles.nkey": type_counts["Key"],
        "handles.nthread": type_counts["Thread"],
        "handles.ndirectory": type_counts["Directory"],
        "handles.nsemaphore": type_counts["Semaphore"],
        "handles.ntimer": type_counts["Timer"],
        "handles.nsection": type_counts["Section"],
        "handles.nmutant": type_counts["Mutant"],
    }


def parse_ldrmodules(rows: list) -> dict:
    """Parse ldrmodules JSON rows for modules not in load/init/mem lists."""
    not_in_load = 0
    not_in_init = 0
    not_in_mem = 0

    for row in rows:
        if not row.get("InLoad", True):
            not_in_load += 1
        if not row.get("InInit", True):
            not_in_init += 1
        if not row.get("InMem", True):
            not_in_mem += 1

    return {
        "ldrmodules.not_in_load": not_in_load,
        "ldrmodules.not_in_init": not_in_init,
        "ldrmodules.not_in_mem": not_in_mem,
    }


def parse_malfind(rows: list) -> dict:
    """Parse malfind JSON rows for injection metrics."""
    if not rows:
        return {
            "malfind.ninjections": 0, "malfind.commitCharge": 0,
            "malfind.protection": 0, "malfind.uniqueInjections": 0,
        }

    total_commit = 0
    protections = set()
    unique_injections = set()

    for row in rows:
        pid = row.get("PID", 0)
        addr = row.get("Start VPN", row.get("Address", 0))
        unique_injections.add((pid, addr))

        commit = row.get("CommitCharge", 0)
        if commit:
            total_commit += int(commit)

        prot = row.get("Protection", "")
        if prot:
            protections.add(str(prot))

    return {
        "malfind.ninjections": len(rows),
        "malfind.commitCharge": total_commit,
        "malfind.protection": len(protections),
        "malfind.uniqueInjections": len(unique_injections),
    }


def parse_psxview(rows: list) -> dict:
    """Parse psxview JSON rows for hidden process indicators.

    Note: psxview is a community plugin in Vol3. If unavailable, features
    default to 0 via the extract_features error handler.
    """
    col_map = {
        "pslist": "pslist",
        "thrdproc": "ethread_pool",
        "pspcid": "pspcid_list",
        "csrss": "csrss_handles",
        "session": "session",
        "deskthrd": "deskthrd",
    }

    counts = {v: 0 for v in col_map.values()}
    total_rows = 0

    for row in rows:
        total_rows += 1
        for json_key, suffix in col_map.items():
            val = row.get(json_key)
            if val is not None and not val:
                counts[suffix] += 1

    result = {}
    for suffix in col_map.values():
        result[f"psxview.not_in_{suffix}"] = counts[suffix]
        result[f"psxview.not_in_{suffix}_false_avg"] = (
            counts[suffix] / total_rows if total_rows > 0 else 0.0
        )

    return result


def parse_svcscan(rows: list) -> dict:
    """Parse svcscan JSON rows for service counts."""
    nservices = len(rows)
    kernel_drivers = 0
    process_services = 0
    nactive = 0

    for row in rows:
        svc_type = str(row.get("Type", row.get("ServiceType", "")))
        state = str(row.get("State", ""))

        if "SERVICE_KERNEL_DRIVER" in svc_type:
            kernel_drivers += 1
        if "SERVICE_WIN32_OWN_PROCESS" in svc_type:
            process_services += 1
        if "SERVICE_RUNNING" in state:
            nactive += 1

    return {
        "svcscan.nservices": nservices,
        "svcscan.kernel_drivers": kernel_drivers,
        "svcscan.process_services": process_services,
        "svcscan.nactive": nactive,
    }


def parse_callbacks(rows: list) -> dict:
    """Parse callbacks JSON rows for callback count."""
    return {"callbacks.ncallbacks": len(rows)}


# Plugin name -> parser function
PARSERS = {
    "pslist": parse_pslist,
    "dlllist": parse_dlllist,
    "handles": parse_handles,
    "ldrmodules": parse_ldrmodules,
    "malfind": parse_malfind,
    "psxview": parse_psxview,
    "svcscan": parse_svcscan,
    "callbacks": parse_callbacks,
}


def apply_log1p(df: pd.DataFrame) -> pd.DataFrame:
    """Apply signed log1p transform to skewed features (must match notebook 02)."""
    df = df.copy()
    for col in LOG1P_FEATURES:
        if col in df.columns:
            df[col] = np.log1p(df[col].abs()) * np.sign(df[col])
    return df


def extract_features(dump_path: str, vol_path: str = "vol",
                     timeout: int = 600, on_progress=None) -> pd.DataFrame:
    """Run all Volatility 3 plugins and return a single-row DataFrame of 38 features.

    Args:
        dump_path: Path to the memory dump file.
        vol_path: Path to the Volatility 3 executable.
        timeout: Max seconds per plugin.
        on_progress: Optional callback(plugin_name, status) for progress reporting.

    Returns:
        Single-row DataFrame with columns matching FEATURE_ORDER.
    """
    dump_path = str(Path(dump_path).resolve())
    if not Path(dump_path).exists():
        raise FileNotFoundError(f"Memory dump not found: {dump_path}")

    features = {}

    for plugin in PLUGINS:
        if on_progress:
            on_progress(plugin, "running")

        try:
            rows = run_plugin(dump_path, plugin, vol_path, timeout)
            parsed = PARSERS[plugin](rows)
            features.update(parsed)

            if on_progress:
                on_progress(plugin, "done")
        except Exception as e:
            if on_progress:
                on_progress(plugin, f"failed: {e}")
            # Fill missing features with 0
            for feat in FEATURE_ORDER:
                if feat.startswith(f"{plugin}.") and feat not in features:
                    features[feat] = 0

    # Build DataFrame in exact column order
    row = {feat: features.get(feat, 0) for feat in FEATURE_ORDER}
    df = pd.DataFrame([row], columns=FEATURE_ORDER)

    return df
