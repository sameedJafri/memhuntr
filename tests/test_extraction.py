"""Tests for extraction module — Volatility 3 JSON output parsers."""

import numpy as np
import pandas as pd
import pytest

from src.extraction import (
    FEATURE_ORDER,
    LOG1P_FEATURES,
    apply_log1p,
    parse_callbacks,
    parse_dlllist,
    parse_handles,
    parse_ldrmodules,
    parse_malfind,
    parse_pslist,
    parse_psxview,
    parse_svcscan,
    _flatten_rows,
)

# ---------------------------------------------------------------------------
# Fixture: sample Volatility 3 JSON rows (list of dicts)
# ---------------------------------------------------------------------------

PSLIST_ROWS = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 84, "Handles": 474},
    {"PID": 248, "PPID": 4, "ImageFileName": "smss.exe", "Threads": 2, "Handles": 29},
    {"PID": 340, "PPID": 332, "ImageFileName": "csrss.exe", "Threads": 9, "Handles": 436},
    {"PID": 388, "PPID": 332, "ImageFileName": "wininit.exe", "Threads": 3, "Handles": 75},
]

DLLLIST_ROWS = [
    {"PID": 340, "Process": "csrss.exe", "Base": "0x04a00000", "Size": "0x5000", "Name": "csrss.exe", "Path": "\\SystemRoot\\System32\\csrss.exe"},
    {"PID": 340, "Process": "csrss.exe", "Base": "0x7c900000", "Size": "0x12000", "Name": "ntdll.dll", "Path": "\\SystemRoot\\System32\\ntdll.dll"},
    {"PID": 388, "Process": "wininit.exe", "Base": "0x00400000", "Size": "0x3000", "Name": "wininit.exe", "Path": "\\SystemRoot\\System32\\wininit.exe"},
    {"PID": 388, "Process": "wininit.exe", "Base": "0x7c900000", "Size": "0x12000", "Name": "ntdll.dll", "Path": "\\SystemRoot\\System32\\ntdll.dll"},
    {"PID": 388, "Process": "wininit.exe", "Base": "0x7c800000", "Size": "0x11000", "Name": "kernel32.dll", "Path": "\\SystemRoot\\System32\\kernel32.dll"},
]

HANDLES_ROWS = [
    {"PID": 4, "Process": "System", "Offset": "0xfffffa8000ca1010", "HandleValue": "0x4", "Type": "Directory", "GrantedAccess": "0x1f0003", "Name": "KnownDlls"},
    {"PID": 4, "Process": "System", "Offset": "0xfffffa8000ca2020", "HandleValue": "0x8", "Type": "Key", "GrantedAccess": "0x1f0003", "Name": "MACHINE"},
    {"PID": 4, "Process": "System", "Offset": "0xfffffa8000ca3030", "HandleValue": "0xc", "Type": "Thread", "GrantedAccess": "0x1f0001", "Name": "TID 100"},
    {"PID": 4, "Process": "System", "Offset": "0xfffffa8000ca4040", "HandleValue": "0x10", "Type": "Mutant", "GrantedAccess": "0x1f0003", "Name": "SomeMutex"},
    {"PID": 340, "Process": "csrss.exe", "Offset": "0xfffffa8000ca5050", "HandleValue": "0x14", "Type": "Section", "GrantedAccess": "0x1f0003", "Name": "BaseNamedObjects"},
    {"PID": 340, "Process": "csrss.exe", "Offset": "0xfffffa8000ca6060", "HandleValue": "0x18", "Type": "Desktop", "GrantedAccess": "0x100020", "Name": "Default"},
    {"PID": 340, "Process": "csrss.exe", "Offset": "0xfffffa8000ca7070", "HandleValue": "0x1c", "Type": "Semaphore", "GrantedAccess": "0x1f0003", "Name": "SomeSemaphore"},
    {"PID": 340, "Process": "csrss.exe", "Offset": "0xfffffa8000ca8080", "HandleValue": "0x20", "Type": "Timer", "GrantedAccess": "0x1f0003", "Name": "SomeTimer"},
]

LDRMODULES_ROWS = [
    {"Pid": 340, "Process": "csrss.exe", "Base": "0x04a00000", "InLoad": True, "InInit": True, "InMem": True, "MappedPath": "\\csrss.exe"},
    {"Pid": 340, "Process": "csrss.exe", "Base": "0x7c900000", "InLoad": True, "InInit": True, "InMem": True, "MappedPath": "\\ntdll.dll"},
    {"Pid": 340, "Process": "csrss.exe", "Base": "0x00010000", "InLoad": False, "InInit": False, "InMem": False, "MappedPath": "\\suspicious.dll"},
    {"Pid": 388, "Process": "wininit.exe", "Base": "0x00400000", "InLoad": True, "InInit": False, "InMem": True, "MappedPath": "\\wininit.exe"},
]

MALFIND_ROWS = [
    {"PID": 1024, "Process": "svchost.exe", "Start VPN": "0x00400000", "End VPN": "0x00401000", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 10, "Tag": "VadS"},
    {"PID": 1024, "Process": "svchost.exe", "Start VPN": "0x00500000", "End VPN": "0x00501000", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 5, "Tag": "VadS"},
    {"PID": 2048, "Process": "explorer.exe", "Start VPN": "0x10000000", "End VPN": "0x10001000", "Protection": "PAGE_EXECUTE_READ", "CommitCharge": 20, "Tag": "VadS"},
]

PSXVIEW_ROWS = [
    {"pslist": True, "thrdproc": True, "pspcid": True, "csrss": False, "session": False, "deskthrd": False, "Name": "System", "PID": 4},
    {"pslist": True, "thrdproc": True, "pspcid": True, "csrss": False, "session": False, "deskthrd": False, "Name": "smss.exe", "PID": 248},
    {"pslist": True, "thrdproc": True, "pspcid": True, "csrss": True, "session": True, "deskthrd": True, "Name": "csrss.exe", "PID": 340},
    {"pslist": False, "thrdproc": False, "pspcid": True, "csrss": True, "session": True, "deskthrd": True, "Name": "svchost.exe", "PID": 1024},
]

SVCSCAN_ROWS = [
    {"Offset": "0x298c40", "Order": 143, "Name": "ACPI", "DisplayName": "Microsoft ACPI Driver", "Type": "SERVICE_KERNEL_DRIVER", "State": "SERVICE_RUNNING", "Binary": "\\SystemRoot\\system32\\drivers\\ACPI.sys"},
    {"Offset": "0x29ab80", "Order": 12, "Name": "AudioSrv", "DisplayName": "Windows Audio", "Type": "SERVICE_WIN32_SHARE_PROCESS", "State": "SERVICE_RUNNING", "Binary": "%SystemRoot%\\System32\\svchost.exe -k netsvcs"},
    {"Offset": "0x29cd00", "Order": 55, "Name": "Spooler", "DisplayName": "Print Spooler", "Type": "SERVICE_WIN32_OWN_PROCESS", "State": "SERVICE_STOPPED", "Binary": "%SystemRoot%\\System32\\spoolsv.exe"},
]

CALLBACKS_ROWS = [
    {"Type": "IoRegisterShutdownNotification", "Callback": "0xfffff80002a12340", "Module": "ACPI.sys", "Detail": "-"},
    {"Type": "CmRegisterCallback", "Callback": "0xfffff80002b34560", "Module": "CI.dll", "Detail": "-"},
    {"Type": "KeBugCheckCallbackListHead", "Callback": "0xfffff80002c56780", "Module": "hal.dll", "Detail": "-"},
]


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParsePslist:
    def test_basic(self):
        result = parse_pslist(PSLIST_ROWS)
        assert result["pslist.nproc"] == 4
        assert result["pslist.nppid"] == 3  # PPIDs: 0, 4, 332
        assert result["pslist.avg_threads"] == pytest.approx((84 + 2 + 9 + 3) / 4)

    def test_empty(self):
        result = parse_pslist([])
        assert result["pslist.nproc"] == 0
        assert result["pslist.avg_threads"] == 0.0


class TestParseDlllist:
    def test_basic(self):
        result = parse_dlllist(DLLLIST_ROWS)
        # csrss.exe: 2 DLLs, wininit.exe: 3 DLLs -> avg 2.5
        assert result["dlllist.avg_dlls_per_proc"] == pytest.approx(2.5)

    def test_empty(self):
        result = parse_dlllist([])
        assert result["dlllist.avg_dlls_per_proc"] == 0.0


class TestParseHandles:
    def test_basic(self):
        result = parse_handles(HANDLES_ROWS)
        assert result["handles.nhandles"] == 8
        assert result["handles.ndirectory"] == 1
        assert result["handles.nkey"] == 1
        assert result["handles.nthread"] == 1
        assert result["handles.nmutant"] == 1
        assert result["handles.nsection"] == 1
        assert result["handles.ndesktop"] == 1
        assert result["handles.nsemaphore"] == 1
        assert result["handles.ntimer"] == 1
        # 2 unique PIDs (4, 340)
        assert result["handles.avg_handles_per_proc"] == pytest.approx(4.0)

    def test_empty(self):
        result = parse_handles([])
        assert result["handles.nhandles"] == 0


class TestParseLdrmodules:
    def test_basic(self):
        result = parse_ldrmodules(LDRMODULES_ROWS)
        assert result["ldrmodules.not_in_load"] == 1   # suspicious.dll
        assert result["ldrmodules.not_in_init"] == 2   # suspicious.dll + wininit.exe
        assert result["ldrmodules.not_in_mem"] == 1    # suspicious.dll

    def test_empty(self):
        result = parse_ldrmodules([])
        assert result["ldrmodules.not_in_load"] == 0


class TestParseMalfind:
    def test_basic(self):
        result = parse_malfind(MALFIND_ROWS)
        assert result["malfind.ninjections"] == 3
        assert result["malfind.commitCharge"] == 35  # 10 + 5 + 20
        assert result["malfind.protection"] == 2     # PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ
        assert result["malfind.uniqueInjections"] == 3

    def test_empty(self):
        result = parse_malfind([])
        assert result["malfind.ninjections"] == 0
        assert result["malfind.commitCharge"] == 0


class TestParsePsxview:
    def test_basic(self):
        result = parse_psxview(PSXVIEW_ROWS)
        assert result["psxview.not_in_pslist"] == 1        # svchost
        assert result["psxview.not_in_ethread_pool"] == 1  # svchost
        assert result["psxview.not_in_csrss_handles"] == 2 # System, smss
        assert result["psxview.not_in_session"] == 2       # System, smss
        assert result["psxview.not_in_deskthrd"] == 2      # System, smss
        assert result["psxview.not_in_pslist_false_avg"] == pytest.approx(0.25)

    def test_empty(self):
        result = parse_psxview([])
        assert result["psxview.not_in_pslist"] == 0
        assert result["psxview.not_in_pslist_false_avg"] == 0.0


class TestParseSvcscan:
    def test_basic(self):
        result = parse_svcscan(SVCSCAN_ROWS)
        assert result["svcscan.nservices"] == 3
        assert result["svcscan.kernel_drivers"] == 1
        assert result["svcscan.process_services"] == 1
        assert result["svcscan.shared_process_services"] == 1
        assert result["svcscan.nactive"] == 2

    def test_empty(self):
        result = parse_svcscan([])
        assert result["svcscan.nservices"] == 0


class TestParseCallbacks:
    def test_basic(self):
        result = parse_callbacks(CALLBACKS_ROWS)
        assert result["callbacks.ncallbacks"] == 3

    def test_empty(self):
        result = parse_callbacks([])
        assert result["callbacks.ncallbacks"] == 0


# ---------------------------------------------------------------------------
# _flatten_rows tests
# ---------------------------------------------------------------------------

class TestFlattenRows:
    def test_flat_list(self):
        data = [{"PID": 4}, {"PID": 248}]
        assert _flatten_rows(data) == [{"PID": 4}, {"PID": 248}]

    def test_nested_children(self):
        data = [{"PID": 4, "__children": [{"PID": 248, "__children": [{"PID": 340}]}]}]
        result = _flatten_rows(data)
        assert len(result) == 3
        assert result[0]["PID"] == 4
        assert result[1]["PID"] == 248
        assert result[2]["PID"] == 340

    def test_dict_wrapper(self):
        data = {"data": [{"PID": 4}]}
        assert _flatten_rows(data) == [{"PID": 4}]

    def test_empty(self):
        assert _flatten_rows([]) == []


# ---------------------------------------------------------------------------
# apply_log1p tests
# ---------------------------------------------------------------------------

class TestApplyLog1p:
    def test_transforms_correct_columns(self):
        row = {feat: 100.0 for feat in FEATURE_ORDER}
        df = pd.DataFrame([row])
        result = apply_log1p(df)

        for col in FEATURE_ORDER:
            if col in LOG1P_FEATURES:
                assert result[col].iloc[0] == pytest.approx(np.log1p(100.0))
            else:
                assert result[col].iloc[0] == 100.0

    def test_signed_log1p(self):
        row = {feat: -50.0 for feat in FEATURE_ORDER}
        df = pd.DataFrame([row])
        result = apply_log1p(df)

        for col in LOG1P_FEATURES:
            assert result[col].iloc[0] == pytest.approx(np.log1p(50.0) * -1)

    def test_zero_values(self):
        row = {feat: 0.0 for feat in FEATURE_ORDER}
        df = pd.DataFrame([row])
        result = apply_log1p(df)

        for col in LOG1P_FEATURES:
            assert result[col].iloc[0] == 0.0

    def test_does_not_modify_original(self):
        row = {feat: 100.0 for feat in FEATURE_ORDER}
        df = pd.DataFrame([row])
        apply_log1p(df)
        assert df[LOG1P_FEATURES[0]].iloc[0] == 100.0


# ---------------------------------------------------------------------------
# Feature constant tests
# ---------------------------------------------------------------------------

class TestFeatureConstants:
    def test_feature_count(self):
        assert len(FEATURE_ORDER) == 39

    def test_log1p_features_subset_of_feature_order(self):
        assert set(LOG1P_FEATURES).issubset(set(FEATURE_ORDER))

    def test_no_duplicate_features(self):
        assert len(FEATURE_ORDER) == len(set(FEATURE_ORDER))
