"""Tests for extraction module — Volatility 2 output parsers."""

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
)

# ---------------------------------------------------------------------------
# Fixture: sample Volatility 2 output strings
# ---------------------------------------------------------------------------

PSLIST_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ -----
0xfffffa8000ca0060 System                    4      0     84      474 ------      0 2023-01-15 10:20:30 UTC+0000
0xfffffa8001a3b060 smss.exe                248      4      2       29 ------      0 2023-01-15 10:20:30 UTC+0000
0xfffffa8002b1d060 csrss.exe               340    332      9      436      0      0 2023-01-15 10:20:31 UTC+0000
0xfffffa8002c5e060 wininit.exe             388    332      3       75      0      0 2023-01-15 10:20:31 UTC+0000
"""

DLLLIST_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
csrss.exe pid:    340
Command line : %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows

Base             Size          LoadCount LoadTime                       Path
---------- ---------- ---------- ------------------------------ ----
0x04a00000     0x5000     0xffff                                \\SystemRoot\\System32\\csrss.exe
0x7c900000    0x12000     0xffff                                \\SystemRoot\\System32\\ntdll.dll

************************************************************************
wininit.exe pid:    388
Command line : wininit.exe

Base             Size          LoadCount LoadTime                       Path
---------- ---------- ---------- ------------------------------ ----
0x00400000     0x3000     0xffff                                \\SystemRoot\\System32\\wininit.exe
0x7c900000    0x12000     0xffff                                \\SystemRoot\\System32\\ntdll.dll
0x7c800000    0x11000     0xffff                                \\SystemRoot\\System32\\kernel32.dll
"""

HANDLES_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
Offset(V)             Pid        Handle           Access Type             Details
------------------ ------ ------------ ---------- ---------------- -------
0xfffffa8000ca1010      4          0x4   0x1f0003 Directory        KnownDlls
0xfffffa8000ca2020      4          0x8   0x1f0003 Key              MACHINE
0xfffffa8000ca3030      4          0xc   0x1f0001 Thread           TID 100
0xfffffa8000ca4040      4         0x10   0x1f0003 Mutant           SomeMutex
0xfffffa8000ca5050    340         0x14   0x1f0003 Section          BaseNamedObjects
0xfffffa8000ca6060    340         0x18   0x100020 Desktop          Default
0xfffffa8000ca7070    340         0x1c   0x1f0003 Semaphore        SomeSemaphore
0xfffffa8000ca8080    340         0x20   0x1f0003 Timer            SomeTimer
"""

LDRMODULES_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
Pid      Process              Base       InLoad InInit InMem  MappedPath
-------- -------------------- ---------- ------ ------ ------ ----------
     340 csrss.exe            0x04a00000 True   True   True   \\csrss.exe
     340 csrss.exe            0x7c900000 True   True   True   \\ntdll.dll
     340 csrss.exe            0x00010000 False  False  False  \\suspicious.dll
     388 wininit.exe          0x00400000 True   False  True   \\wininit.exe
"""

MALFIND_OUTPUT = """\
Process: svchost.exe Pid: 1024 Address: 0x00400000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 10, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00400000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............

Process: svchost.exe Pid: 1024 Address: 0x00500000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 5, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00500000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............

Process: explorer.exe Pid: 2048 Address: 0x10000000
Vad Tag: VadS Protection: PAGE_EXECUTE_READ
Flags: CommitCharge: 20, MemCommit: 1, PrivateMemory: 1, Protection: 5

0x10000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
"""

PSXVIEW_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Name                    PID pslist psscan thrdproc pspcid csrss  session deskthrd
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------- --------
0x000000003fd02060 System                    4 True   True   True     True   False  False   False
0x000000003e4ab060 smss.exe                248 True   True   True     True   False  False   False
0x000000003e2d8960 csrss.exe               340 True   True   True     True   True   True    True
0x000000003e2a5060 svchost.exe            1024 False  True   False    True   True   True    True
"""

SVCSCAN_OUTPUT = """\
Offset: 0x298c40
Order: 143
Start: SERVICE_AUTO_START
Process ID: -
Service Name: ACPI
Display Name: Microsoft ACPI Driver
Service Type: SERVICE_KERNEL_DRIVER
State           : SERVICE_RUNNING
Binary Path: \\SystemRoot\\system32\\drivers\\ACPI.sys

Offset: 0x29ab80
Order: 12
Start: SERVICE_AUTO_START
Process ID: 680
Service Name: AudioSrv
Display Name: Windows Audio
Service Type: SERVICE_WIN32_SHARE_PROCESS
State           : SERVICE_RUNNING
Binary Path: %SystemRoot%\\System32\\svchost.exe -k netsvcs

Offset: 0x29cd00
Order: 55
Start: SERVICE_DEMAND_START
Process ID: 1200
Service Name: Spooler
Display Name: Print Spooler
Service Type: SERVICE_WIN32_OWN_PROCESS
State           : SERVICE_STOPPED
Binary Path: %SystemRoot%\\System32\\spoolsv.exe
"""

CALLBACKS_OUTPUT = """\
Volatility Foundation Volatility Framework 2.6.1
Type                                 Callback           Module               Detail
------------------------------------ ------------------ -------------------- ------
IoRegisterShutdownNotification       0xfffff80002a12340 ACPI.sys             -
CmRegisterCallback                   0xfffff80002b34560 CI.dll               -
KeBugCheckCallbackListHead           0xfffff80002c56780 hal.dll              -
"""


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParsePslist:
    def test_basic(self):
        result = parse_pslist(PSLIST_OUTPUT)
        assert result["pslist.nproc"] == 4
        assert result["pslist.nppid"] == 3  # PPIDs: 0, 4, 332
        assert result["pslist.avg_threads"] == pytest.approx((84 + 2 + 9 + 3) / 4)

    def test_empty(self):
        result = parse_pslist("")
        assert result["pslist.nproc"] == 0
        assert result["pslist.avg_threads"] == 0.0


class TestParseDlllist:
    def test_basic(self):
        result = parse_dlllist(DLLLIST_OUTPUT)
        # csrss.exe: 2 DLLs, wininit.exe: 3 DLLs -> avg 2.5
        assert result["dlllist.avg_dlls_per_proc"] == pytest.approx(2.5)

    def test_empty(self):
        result = parse_dlllist("")
        assert result["dlllist.avg_dlls_per_proc"] == 0.0


class TestParseHandles:
    def test_basic(self):
        result = parse_handles(HANDLES_OUTPUT)
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
        result = parse_handles("")
        assert result["handles.nhandles"] == 0


class TestParseLdrmodules:
    def test_basic(self):
        result = parse_ldrmodules(LDRMODULES_OUTPUT)
        assert result["ldrmodules.not_in_load"] == 1   # suspicious.dll
        assert result["ldrmodules.not_in_init"] == 2   # suspicious.dll + wininit.exe
        assert result["ldrmodules.not_in_mem"] == 1    # suspicious.dll

    def test_empty(self):
        result = parse_ldrmodules("")
        assert result["ldrmodules.not_in_load"] == 0


class TestParseMalfind:
    def test_basic(self):
        result = parse_malfind(MALFIND_OUTPUT)
        assert result["malfind.ninjections"] == 3
        assert result["malfind.commitCharge"] == 35  # 10 + 5 + 20
        assert result["malfind.protection"] == 4     # 2 Protection: lines + 2 Protection: in Flags per unique value
        assert result["malfind.uniqueInjections"] == 3

    def test_empty(self):
        result = parse_malfind("")
        assert result["malfind.ninjections"] == 0
        assert result["malfind.commitCharge"] == 0


class TestParsePsxview:
    def test_basic(self):
        result = parse_psxview(PSXVIEW_OUTPUT)
        assert result["psxview.not_in_pslist"] == 1        # svchost
        assert result["psxview.not_in_ethread_pool"] == 1  # svchost
        assert result["psxview.not_in_csrss_handles"] == 2 # System, smss
        assert result["psxview.not_in_session"] == 2       # System, smss
        assert result["psxview.not_in_deskthrd"] == 2      # System, smss
        assert result["psxview.not_in_pslist_false_avg"] == pytest.approx(0.25)

    def test_empty(self):
        result = parse_psxview("")
        assert result["psxview.not_in_pslist"] == 0
        assert result["psxview.not_in_pslist_false_avg"] == 0.0


class TestParseSvcscan:
    def test_basic(self):
        result = parse_svcscan(SVCSCAN_OUTPUT)
        assert result["svcscan.nservices"] == 3
        assert result["svcscan.kernel_drivers"] == 1
        assert result["svcscan.process_services"] == 1
        assert result["svcscan.shared_process_services"] == 1
        assert result["svcscan.nactive"] == 2

    def test_empty(self):
        result = parse_svcscan("")
        assert result["svcscan.nservices"] == 0


class TestParseCallbacks:
    def test_basic(self):
        result = parse_callbacks(CALLBACKS_OUTPUT)
        assert result["callbacks.ncallbacks"] == 3

    def test_empty(self):
        result = parse_callbacks("")
        assert result["callbacks.ncallbacks"] == 0


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
