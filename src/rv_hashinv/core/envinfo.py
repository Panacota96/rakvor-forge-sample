"""environment.json: what ran, where, with which exact dependency versions (repeatability)."""

from __future__ import annotations

import getpass
import os
import platform
import re
import socket
import ssl
import sys
from importlib import metadata

from .timeutil import utc_now

DISTRIBUTION = "rv-hashinv"
# Used when the package metadata of this tool is not available (some frozen builds): the direct runtime
# dependencies and the libraries that compute evidence digests, timestamp requests and report signatures.
# packaging/build_windows.py embeds the metadata of exactly these distributions in the frozen build.
TRACKED = (
    "click",
    "rich",
    "blake3",
    "jinja2",
    "reportlab",
    "pyhanko",
    "pyhanko-certvalidator",
    "asn1crypto",
    "cryptography",
    "cffi",
    "PySide6-Essentials",
    "shiboken6",
)
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXTRAS = re.compile(r"\[([^\]]*)\]")
_EXTRA = re.compile(r"extra\s*==\s*['\"]([^'\"]+)['\"]")


def os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user database in some containers
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _installed(name: str) -> metadata.Distribution | None:
    try:
        return metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return None


def dependencies() -> list[str]:
    """name@version of every installed runtime dependency of this tool, transitively (the Python counterpart of the
    Cargo.lock entries the Rust profile records): requirements of rv-hashinv (all its extras, e.g. gui), then
    theirs (only the extras actually requested), and so on. A requirement that is not installed (another platform,
    an extra not chosen) is skipped. Sorted by name."""
    found: dict[str, str] = {}
    root = _installed(DISTRIBUTION)
    # (requirement string, extras requested of the requiring distribution; None = every extra)
    queue: list[tuple[str, set[str] | None]] = [(r, None) for r in (root.requires or [])] if root is not None else [(n, set()) for n in TRACKED]
    seen: set[str] = set()
    while queue:
        req, parent_extras = queue.pop()
        spec, _, marker = req.partition(";")
        m = _NAME.match(spec)
        if not m:
            continue
        needs = _EXTRA.search(marker)
        if needs and parent_extras is not None and needs.group(1).lower() not in parent_extras:
            continue
        extras = {e.strip().lower() for e in _EXTRAS.search(spec).group(1).split(",")} if _EXTRAS.search(spec) else set()
        key = m.group(1).lower().replace("_", "-").replace(".", "-")
        d = _installed(m.group(1))
        if d is None or (key in seen and not extras):
            continue
        seen.add(key)
        found[key] = f"{d.metadata['Name'] or m.group(1)}@{d.version}"
        queue += [(r, extras) for r in (d.requires or [])]
    return [found[k] for k in sorted(found)]


def openssl() -> dict:
    """OpenSSL builds in use: Python's ssl/hashlib (MD5, SHA-1, SHA-2, SHA-3 digests and the TSA's HTTPS) and the
    one bundled in `cryptography` (certificate and key handling for the report signatures)."""
    out = {"python_ssl": ssl.OPENSSL_VERSION}
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        out["cryptography"] = backend.openssl_version_text()
    except Exception as e:  # noqa: BLE001 - optional detail; never fail a run for it
        out["cryptography"] = f"unknown ({type(e).__name__})"
    return out


def describe(tool: str, version: str, frontend: str, command_line: list[str]) -> dict:
    return {
        "tool": {
            "name": tool,
            "version": version,
            "frontend": frontend,
            "python": sys.version.split()[0],
            "openssl": openssl(),
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
