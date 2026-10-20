"""Turns user input (files, folders, list files) into a sorted, de-duplicated list of evidence items."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Item:
    index: int
    path: Path
    size: int


def collect(inputs: list[Path], list_file: Path | None = None, recursive: bool = False) -> list[Item]:
    """Folders are read one level deep unless `recursive`. Symbolic links are never followed."""
    paths = list(inputs)
    if list_file is not None:
        try:
            text = Path(list_file).read_text(encoding="utf-8-sig")
        except OSError as e:
            raise ValueError(f"cannot read list file {list_file}: {e}") from e
        base = Path(list_file).parent
        for line in (ln.strip() for ln in text.splitlines()):
            if line and not line.startswith("#"):
                p = Path(line)
                paths.append(p if p.is_absolute() else base / p)
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
    ordered = sorted(files, key=lambda q: str(q))
    return [Item(i + 1, Path(os.path.abspath(q)), q.stat().st_size) for i, q in enumerate(ordered)]
