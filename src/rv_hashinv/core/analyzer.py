"""Domain logic — THE PART EACH NEW TOOL REPLACES.

This reference analyzer inventories evidence: it detects the real file type from its signature
(magic bytes) and flags extension mismatches, programs under other names and empty files.
Duplicates are found later, across items, by run.py. A new tool keeps the `analyze` signature
and the Finding shape so audit, reports, CLI and GUI work unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePath

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    code: str
    severity: str  # info | low | medium | high
    params: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"code": self.code, "severity": self.severity, "params": dict(sorted(self.params.items()))}


@dataclass
class Analysis:
    detected_type: str | None
    extension: str | None
    findings: list[Finding]


# (name, offset, magic, expected extensions, executable)
SIGNATURES = [
    ("PDF document", 0, b"%PDF-", ("pdf",), False),
    ("PNG image", 0, b"\x89PNG\r\n\x1a\n", ("png",), False),
    ("JPEG image", 0, b"\xff\xd8\xff", ("jpg", "jpeg", "jpe", "jfif"), False),
    ("GIF image", 0, b"GIF8", ("gif",), False),
    ("ZIP / Office Open XML", 0, b"PK\x03\x04", ("zip", "docx", "xlsx", "pptx", "odt", "ods", "jar", "apk", "epub"), False),
    ("OLE2 (legacy Office, MSG)", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ("doc", "xls", "ppt", "msg"), False),
    ("Windows executable (PE)", 0, b"MZ", ("exe", "dll", "sys", "scr", "com", "efi"), True),
    ("Linux executable (ELF)", 0, b"\x7fELF", ("so", "bin", "elf", "o"), True),
    ("SQLite database", 0, b"SQLite format 3\x00", ("db", "sqlite", "sqlite3"), False),
    ("7-Zip archive", 0, b"7z\xbc\xaf\x27\x1c", ("7z",), False),
    ("RAR archive", 0, b"Rar!\x1a\x07", ("rar",), False),
    ("GZIP archive", 0, b"\x1f\x8b", ("gz", "tgz"), False),
    ("Windows event log (EVTX)", 0, b"ElfFile\x00", ("evtx",), False),
    ("Windows registry hive", 0, b"regf", ("dat", "hve"), False),
    ("MP4 / QuickTime video", 4, b"ftyp", ("mp4", "m4v", "mov", "m4a", "3gp", "heic"), False),
]
TEXT_EXTENSIONS = ("txt", "csv", "log", "xml", "json", "html")


def detect(head: bytes):
    for sig in SIGNATURES:
        _, off, magic, _, _ = sig
        if head[off : off + len(magic)] == magic:
            return sig
    return None


def analyze(file_name: str, size: int, head: bytes) -> Analysis:
    suffix = PurePath(file_name).suffix
    ext = suffix[1:].lower() if suffix else None
    sig = detect(head)
    findings: list[Finding] = []
    if size == 0:
        findings.append(Finding("EMPTY_FILE", "info"))
    if sig and ext:
        name, _, _, exts, executable = sig
        if ext not in exts:
            if executable:
                findings.append(Finding("EXECUTABLE_CONTENT", "high", {"detected": name, "extension": ext}))
            elif any(ext in s[3] for s in SIGNATURES) or ext in TEXT_EXTENSIONS:
                findings.append(Finding("EXTENSION_MISMATCH", "medium", {"detected": name, "extension": ext}))
    return Analysis(sig[0] if sig else None, ext, findings)
