"""Run Volatility 2 plugins on a memory dump and extract features for classification."""

import os
import re
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
    "svcscan.shared_process_services", "svcscan.nactive",
    "callbacks.ncallbacks",
]

# Features that require signed log1p transform before scaling (matches notebook 02)
LOG1P_FEATURES = [
    "handles.avg_handles_per_proc", "handles.nhandles", "handles.nsection",
    "malfind.commitCharge", "malfind.ninjections", "malfind.protection",
    "psxview.not_in_csrss_handles", "psxview.not_in_deskthrd",
    "psxview.not_in_ethread_pool",
    "svcscan.kernel_drivers", "svcscan.nservices", "svcscan.shared_process_services",
]

# Volatility 2 plugins to run
PLUGINS = ["pslist", "dlllist", "handles", "ldrmodules", "malfind", "psxview",
           "svcscan", "callbacks"]


def check_volatility(vol_path: str = None) -> str:
    """Verify Volatility 2 is installed and return the command path."""
    cmd = vol_path or os.environ.get("VOLATILITY_PATH", "vol.py")
    try:
        result = subprocess.run(
            [cmd, "--info"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and "Address Spaces" in result.stdout:
            return cmd
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    raise RuntimeError(
        f"Volatility 2 not found at '{cmd}'. Install it or set VOLATILITY_PATH.\n"
        "See: https://github.com/volatilityfoundation/volatility"
    )


def run_plugin(dump_path: str, profile: str, plugin: str,
               vol_path: str = "vol.py", timeout: int = 600) -> str:
    """Execute a single Volatility 2 plugin and return its stdout."""
    cmd = [vol_path, "-f", dump_path, f"--profile={profile}", plugin]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise subprocess.SubprocessError(
            f"Plugin '{plugin}' failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Parsers — each takes raw text output and returns a dict of feature values
# ---------------------------------------------------------------------------

def parse_pslist(output: str) -> dict:
    """Parse pslist output for process counts and thread averages."""
    rows = _parse_table_rows(output)
    if not rows:
        return {"pslist.nproc": 0, "pslist.nppid": 0, "pslist.avg_threads": 0.0}

    pids = []
    ppids = []
    threads = []
    for row in rows:
        cols = row.split()
        if len(cols) < 6:
            continue
        try:
            pids.append(int(cols[2]))
            ppids.append(int(cols[3]))
            threads.append(int(cols[4]))
        except (ValueError, IndexError):
            continue

    return {
        "pslist.nproc": len(pids),
        "pslist.nppid": len(set(ppids)),
        "pslist.avg_threads": np.mean(threads) if threads else 0.0,
    }


def parse_dlllist(output: str) -> dict:
    """Parse dlllist output for average DLLs per process."""
    # dlllist output has process headers followed by DLL rows
    # Process header: "****************** ... ********************"
    # followed by: "ProcessName pid: NNN"
    # then: "Base Size LoadCount Path" table rows
    blocks = re.split(r"\*{10,}", output)
    dll_counts = []

    for block in blocks:
        lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
        # Count lines that look like DLL entries (start with 0x hex address)
        dlls = sum(1 for l in lines if re.match(r"^0x[0-9a-fA-F]+", l))
        if dlls > 0:
            dll_counts.append(dlls)

    avg = np.mean(dll_counts) if dll_counts else 0.0
    return {"dlllist.avg_dlls_per_proc": avg}


def parse_handles(output: str) -> dict:
    """Parse handles output for counts by type."""
    rows = _parse_table_rows(output)

    type_counts = {
        "Desktop": 0, "Key": 0, "Thread": 0, "Directory": 0,
        "Semaphore": 0, "Timer": 0, "Section": 0, "Mutant": 0,
    }
    pids = set()
    total = 0

    for row in rows:
        cols = row.split()
        if len(cols) < 5:
            continue
        try:
            pid = int(cols[1])
            handle_type = cols[4]
        except (ValueError, IndexError):
            continue

        total += 1
        pids.add(pid)
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


def parse_ldrmodules(output: str) -> dict:
    """Parse ldrmodules output for modules not in load/init/mem lists."""
    rows = _parse_table_rows(output)

    not_in_load = 0
    not_in_init = 0
    not_in_mem = 0

    for row in rows:
        cols = row.split()
        if len(cols) < 6:
            continue
        # Columns: Pid Process Base InLoad InInit InMem MappedPath
        try:
            in_load = cols[3]
            in_init = cols[4]
            in_mem = cols[5]
        except IndexError:
            continue

        if in_load.lower() == "false":
            not_in_load += 1
        if in_init.lower() == "false":
            not_in_init += 1
        if in_mem.lower() == "false":
            not_in_mem += 1

    return {
        "ldrmodules.not_in_load": not_in_load,
        "ldrmodules.not_in_init": not_in_init,
        "ldrmodules.not_in_mem": not_in_mem,
    }


def parse_malfind(output: str) -> dict:
    """Parse malfind block-based output for injection metrics."""
    # Split on "Process:" lines to get individual injection blocks
    blocks = re.split(r"(?=^Process:)", output, flags=re.MULTILINE)
    blocks = [b.strip() for b in blocks if b.strip() and b.strip().startswith("Process:")]

    if not blocks:
        return {
            "malfind.ninjections": 0, "malfind.commitCharge": 0,
            "malfind.protection": 0, "malfind.uniqueInjections": 0,
        }

    total_commit = 0
    protections = set()
    unique_injections = set()

    for block in blocks:
        lines = block.splitlines()
        first_line = lines[0]

        # Extract PID
        pid_match = re.search(r"Pid:\s*(\d+)", first_line)
        pid = int(pid_match.group(1)) if pid_match else 0

        # Extract address
        addr_match = re.search(r"Address:\s*(0x[0-9a-fA-F]+)", first_line)
        addr = addr_match.group(1) if addr_match else "0x0"

        unique_injections.add((pid, addr))

        # Extract commit charge from Vad Tag line or flags
        for line in lines:
            commit_match = re.search(r"CommitCharge:\s*(\d+)", line)
            if commit_match:
                total_commit += int(commit_match.group(1))

            prot_match = re.search(r"Protection:\s*(\S+)", line)
            if prot_match:
                protections.add(prot_match.group(1))

    return {
        "malfind.ninjections": len(blocks),
        "malfind.commitCharge": total_commit,
        "malfind.protection": len(protections),
        "malfind.uniqueInjections": len(unique_injections),
    }


def parse_psxview(output: str) -> dict:
    """Parse psxview output for hidden process indicators."""
    rows = _parse_table_rows(output)

    # Column mapping: psxview column name -> our feature suffix
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

    # Find header to determine column positions
    header_cols = None
    for row in rows:
        lower = row.lower()
        if "pslist" in lower and "pspcid" in lower:
            header_cols = row.split()
            continue
        if header_cols is None:
            continue

        cols = row.split()
        if len(cols) < len(header_cols):
            continue

        total_rows += 1
        for i, hcol in enumerate(header_cols):
            hcol_lower = hcol.lower()
            if hcol_lower in col_map and i < len(cols):
                if cols[i].lower() == "false":
                    counts[col_map[hcol_lower]] += 1

    # If we couldn't parse the header, try positional parsing
    if header_cols is None:
        total_rows, counts = _parse_psxview_positional(rows)

    result = {}
    for suffix in col_map.values():
        result[f"psxview.not_in_{suffix}"] = counts[suffix]
        result[f"psxview.not_in_{suffix}_false_avg"] = (
            counts[suffix] / total_rows if total_rows > 0 else 0.0
        )

    return result


def _parse_psxview_positional(rows: list) -> tuple:
    """Fallback positional parser for psxview when header detection fails."""
    col_names = ["pslist", "ethread_pool", "pspcid_list",
                 "csrss_handles", "session", "deskthrd"]
    counts = {name: 0 for name in col_names}
    total = 0

    for row in rows:
        cols = row.split()
        if len(cols) < 9:
            continue
        # Typical layout: Offset Name PID pslist psscan thrdproc pspcid csrss session deskthrd
        try:
            bools = cols[3:10]  # pslist through deskthrd
            if not all(b.lower() in ("true", "false") for b in bools):
                continue
        except IndexError:
            continue

        total += 1
        # Map positions: 3=pslist, 5=thrdproc, 6=pspcid, 7=csrss, 8=session, 9=deskthrd
        mapping = [(3, "pslist"), (5, "ethread_pool"), (6, "pspcid_list"),
                   (7, "csrss_handles"), (8, "session"), (9, "deskthrd")]
        for idx, name in mapping:
            if idx < len(cols) and cols[idx].lower() == "false":
                counts[name] += 1

    return total, counts


def parse_svcscan(output: str) -> dict:
    """Parse svcscan block-based output for service counts."""
    # svcscan outputs blocks separated by blank lines
    blocks = re.split(r"\n\s*\n", output)

    nservices = 0
    kernel_drivers = 0
    process_services = 0
    shared_process_services = 0
    nactive = 0

    for block in blocks:
        if not block.strip():
            continue

        lines = block.strip().splitlines()
        is_service = False
        svc_type = ""
        state = ""

        for line in lines:
            line = line.strip()
            if line.startswith("Service Name:"):
                is_service = True
            elif line.startswith("Service Type:"):
                svc_type = line.split(":", 1)[1].strip()
            elif line.startswith("State"):
                state = line.split(":", 1)[1].strip() if ":" in line else ""

        if not is_service:
            continue

        nservices += 1

        if "SERVICE_KERNEL_DRIVER" in svc_type:
            kernel_drivers += 1
        if "SERVICE_WIN32_OWN_PROCESS" in svc_type:
            process_services += 1
        if "SERVICE_WIN32_SHARE_PROCESS" in svc_type:
            shared_process_services += 1
        if "SERVICE_RUNNING" in state:
            nactive += 1

    return {
        "svcscan.nservices": nservices,
        "svcscan.kernel_drivers": kernel_drivers,
        "svcscan.process_services": process_services,
        "svcscan.shared_process_services": shared_process_services,
        "svcscan.nactive": nactive,
    }


def parse_callbacks(output: str) -> dict:
    """Parse callbacks output for callback count."""
    rows = _parse_table_rows(output)
    return {"callbacks.ncallbacks": len(rows)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_table_rows(output: str) -> list:
    """Extract data rows from a Volatility table output (skip headers/separators)."""
    lines = output.strip().splitlines()
    rows = []
    past_header = False

    for line in lines:
        stripped = line.strip()
        # Header separator is a line of dashes
        if re.match(r"^[-\s]+$", stripped) and len(stripped) > 5:
            past_header = True
            continue
        if past_header and stripped:
            rows.append(stripped)

    return rows


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


def extract_features(dump_path: str, profile: str, vol_path: str = "vol.py",
                     timeout: int = 600, on_progress=None) -> pd.DataFrame:
    """Run all Volatility plugins and return a single-row DataFrame of 39 features.

    Args:
        dump_path: Path to the memory dump file.
        profile: Volatility 2 profile string (e.g. 'Win7SP1x64').
        vol_path: Path to the Volatility 2 executable.
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
            output = run_plugin(dump_path, profile, plugin, vol_path, timeout)
            parsed = PARSERS[plugin](output)
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
