"""Freezes the CLI and the GUI with Nuitka into one standalone folder: dist/rv-hashinv/.

Standalone (folder), not onefile: onefile unpacks to %TEMP% at every start, which is slower and a
frequent antivirus false positive. PySide6 stays as separate DLLs (LGPL-3.0 compliance).

Usage: uv run python packaging/build_windows.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from rv_hashinv.core.envinfo import DISTRIBUTION, TRACKED  # noqa: E402
DIST = ROOT / "dist"
VERSION = "0.1.0"  # x-release-please-version

COMMON = [
    sys.executable, "-m", "nuitka", "--standalone", "--assume-yes-for-downloads", "--remove-output",
    f"--output-dir={DIST / 'build'}",
    "--include-package-data=rv_hashinv",
    f"--windows-icon-from-ico={ROOT / 'src' / 'rv_hashinv' / 'resources' / 'brand' / 'rv.ico'}",
    "--company-name=Rakvor", "--product-name=RV HashInv",
    f"--file-version={VERSION}", f"--product-version={VERSION}",
    # environment.json lists dependency versions from package metadata (core/envinfo.py): embed it.
    f"--include-distribution-metadata={DISTRIBUTION}",
    *(f"--include-distribution-metadata={name}" for name in TRACKED),
]


def build(entry: Path, name: str, extra: list[str]) -> Path:
    exe = f"{name}.exe" if sys.platform == "win32" else name
    cmd = [*COMMON, f"--output-filename={exe}", *extra, str(entry)]
    print(" ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT)
    return DIST / "build" / f"{entry.stem}.dist"


def main() -> None:
    shutil.rmtree(DIST, ignore_errors=True)
    entries = ROOT / "packaging" / "entry"
    cli = build(entries / "rv_hashinv_cli.py", "rv-hashinv", ["--windows-console-mode=force"])
    gui = build(entries / "rv_hashinv_gui.py", "rv-hashinv-gui", ["--enable-plugin=pyside6", "--windows-console-mode=disable"])
    target = DIST / "rv-hashinv"
    shutil.copytree(gui, target)
    # Merge the CLI build into the same folder (shared Python runtime and packages).
    shutil.copytree(cli, target, dirs_exist_ok=True)
    for f in ("README.md", "LICENSE", "NOTICE", "CHANGELOG.md"):
        shutil.copy2(ROOT / f, target / f)
    print(f"built {target}")


if __name__ == "__main__":
    main()
