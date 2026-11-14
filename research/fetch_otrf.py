"""Download the public attack captures used by run_otrf.py into a folder you name.

    python research/fetch_otrf.py <empty-or-new-folder>

Source: https://github.com/OTRF/Security-Datasets (a public research repository). The files are
zip archives of Windows event logs from lab attacks, about 4.5 MB together. They are downloaded
as data and never executed or extracted; each file is checked against the SHA-256 recorded when
the results in research/results were produced, so a changed file is refused.

Use a folder that is not inside the project's source tree, and read the repository's own
README for its terms.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"
FILES = {
    "empire_schtasks_creation_standard_user.zip": ("persistence", "b073a18420c90394cd2b6ad7589c78d90eba32dc155ed04b12ac824a8fc591b4"),
    "empire_psexec_dcerpc_tcp_svcctl.zip": ("lateral_movement", "8f40e7fc86bbbf31ebd50b3ba537cf0f4378392ae3e74de84bee00aeb0de1fa5"),
    "empire_wmic_add_user_backdoor.zip": ("lateral_movement", "88502d9a8d90f17aa638d7331120d52e7295480ea5fc4a156463399181d1c6e1"),
    "auditpol_system_user_auditpolicy_modification.zip": ("defense_evasion", "5eb1776e7e9f79060a87ed9efcce0eebbab7940f8f51db8b2d67368c64e2187d"),
    "empire_launcher_vbs.zip": ("execution", "812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c"),
    "cmd_mshta_vbscript_execute_psh.zip": ("defense_evasion", "f5f700bc986bbe73edcc209754b28a3e0ad38c56877f7fc5ed6fd04bc036d9f4"),
    "empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip": ("lateral_movement", "96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88"),
    "covenant_sharpwmi_create_dcerpc_wmi.zip": ("lateral_movement", "6ff5d99660a2ce3691d198e63398ea50d8112472c469c756eeb82b83440ce626"),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    failed = 0
    for name, (tactic, digest) in FILES.items():
        target = folder / name
        if target.exists():
            print(f"{name}: already there")
            continue
        url = f"{BASE}/{tactic}/host/{name}"
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed https URL
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            print(f"{name}: SHA-256 does not match the recorded value; not saved")
            failed += 1
            continue
        target.write_bytes(data)
        print(f"{name}: saved ({len(data)} bytes)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
