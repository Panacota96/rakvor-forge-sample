"""Turns user input (files, folders, list files) into a sorted, de-duplicated list of evidence items.

Item order (shared with the Rust profile, so both number the same input identically): every path is made
absolute and lexically normalised (case.normalize_path), duplicates are dropped, and the items are sorted by
that string, bytewise (UTF-8). Item 1 is the smallest path.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Item:
    index: int
    path: Path
    size: int


def normalize_path(p: Path | str) -> str:
    """Absolute, lexically normalised path (no . / ..): the form stored in the registry and the sort key."""
    return os.path.normpath(os.path.abspath(str(p)))


def sort_key(normalized: str) -> bytes:
    """Bytewise UTF-8 order (the Rust profile sorts the same strings as bytes)."""
    return normalized.encode("utf-8", "surrogateescape")


def read_list(list_file: Path) -> list[Path]:
    """Paths of an --input-list file: one per line, # comments and blank lines ignored, a UTF-8 byte order mark
    (Notepad) stripped, relative paths resolved from the list file's folder."""
    try:
        text = Path(list_file).read_text(encoding="utf-8-sig")
    except OSError as e:
        raise ValueError(f"cannot read list file {list_file}: {e}") from e
    base = Path(list_file).parent
    out = []
    for line in (ln.strip() for ln in text.splitlines()):
        if line and not line.startswith("#"):
            p = Path(line)
            out.append(p if p.is_absolute() else base / p)
    return out


def collect(inputs: list[Path], list_file: Path | None = None, recursive: bool = False) -> list[Item]:
    """Folders are read one level deep unless `recursive`. Symbolic links are never followed."""
    paths = list(inputs)
    if list_file is not None:
        paths += read_list(list_file)
    if not paths:
        raise ValueError("no input given: use --input FILE|FOLDER or --input-list FILE")
    files: set[Path] = set()
    for p in paths:
        if p.is_symlink():
            raise ValueError(f"{p} is neither a file nor a folder (symbolic links are not followed)")
        if p.is_file():
            files.add(p)
        elif p.is_dir():
            if recursive:
                for root, dirs, names in os.walk(p, followlinks=False):
                    dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
                    files.update(Path(root) / n for n in names if (Path(root) / n).is_file() and not (Path(root) / n).is_symlink())
            else:
                files.update(c for c in p.iterdir() if c.is_file() and not c.is_symlink())
        elif not p.exists():
            raise ValueError(f"cannot access {p}: no such file or folder")
        else:
            raise ValueError(f"{p} is neither a file nor a folder")
    unique = {normalize_path(q): q for q in files}
    ordered = sorted(unique, key=sort_key)
    return [Item(i + 1, Path(n), unique[n].stat().st_size) for i, n in enumerate(ordered)]
