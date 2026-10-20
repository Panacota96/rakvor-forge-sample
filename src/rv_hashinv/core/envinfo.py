"""environment.json: what ran, where, with which exact dependency versions (repeatability)."""

from __future__ import annotations

import getpass
import os
import platform
import socket
import sys
from importlib import metadata

from .timeutil import utc_now

TRACKED = ("click", "rich", "blake3", "jinja2", "reportlab", "PySide6-Essentials", "shiboken6")


def os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user database in some containers
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def dependencies() -> list[str]:
    out = []
    for name in TRACKED:
        try:
            out.append(f"{name}@{metadata.version(name)}")
        except metadata.PackageNotFoundError:
            pass
    return out


def describe(tool: str, version: str, frontend: str, command_line: list[str]) -> dict:
    return {
        "tool": {
            "name": tool,
            "version": version,
            "frontend": frontend,
            "python": sys.version.split()[0],
            "frozen": bool(getattr(sys, "frozen", False) or "__compiled__" in globals()),
        },
        "os": {
            "family": os.name,
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
        },
        "host": socket.gethostname(),
        "os_user": os_user(),
        "working_directory": os.getcwd(),
        "command_line": command_line,
        "recorded_utc": utc_now(),
        "dependencies": dependencies(),
    }
