"""Hashing: one read pass feeds one or two digests (never more)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

import blake3

CHUNK = 1 << 20
ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3-256", "blake3")
MAX_SELECTED = 2

KNOWN_ANSWERS = {  # input b"abc"
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "sha3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}


def parse(name: str) -> str | None:
    n = name.strip().lower().replace("_", "-")
    if n == "sha3":
        n = "sha3-256"
    return n if n in ALGORITHMS else None


def validate_selection(algos: list[str]) -> None:
    """Raises ValueError for empty, duplicated or more-than-two selections."""
    if not algos:
        raise ValueError("select at least one hash algorithm")
    if len(algos) > MAX_SELECTED:
        raise ValueError(f"at most {MAX_SELECTED} hash algorithms can run at the same time (got {len(algos)})")
    if len(set(algos)) != len(algos):
        raise ValueError("the same hash algorithm was selected twice")
    unknown = [a for a in algos if a not in ALGORITHMS]
    if unknown:
        raise ValueError(f"unknown hash algorithm '{unknown[0]}': use {', '.join(ALGORITHMS)}")


def new_hasher(algo: str):
    if algo == "blake3":
        return blake3.blake3()
    # usedforsecurity=False: MD5/SHA-1 stay available on FIPS-restricted Windows builds (integrity, not security).
    return hashlib.new(algo.replace("-", "_"), usedforsecurity=False)


@dataclass
class HashOutcome:
    digests: list[tuple[str, str]]
    bytes: int
    head: bytes  # first <= 4 KiB, for signature detection without a second read


def hash_stream(stream: BinaryIO, algos: list[str], on_chunk: Callable[[int], bool] = lambda n: True) -> HashOutcome | None:
    """Reads `stream` once; `on_chunk(bytes_so_far)` returning False cancels (-> None)."""
    validate_selection(algos)
    hashers = [(a, new_hasher(a)) for a in algos]
    total, head = 0, b""
    while True:
        buf = stream.read(CHUNK)
        if not buf:
            break
        if len(head) < 4096:
            head += buf[: 4096 - len(head)]
        for _, h in hashers:
            h.update(buf)
        total += len(buf)
        if not on_chunk(total):
            return None
    return HashOutcome([(a, h.hexdigest()) for a, h in hashers], total, head)


def hash_bytes(data: bytes, algo: str) -> str:
    h = new_hasher(algo)
    h.update(data)
    return h.hexdigest()


def self_test() -> list[str]:
    """Algorithms whose known answer for b'abc' is wrong (empty list = all good)."""
    return [a for a, want in KNOWN_ANSWERS.items() if hash_bytes(b"abc", a) != want]
