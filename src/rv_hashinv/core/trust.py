"""Trust features: RFC 3161 timestamps of the audit chain and digital signatures on PDF reports.

Timestamp
  The head of the audit chain (the entry_hash of the last entry, itself a SHA-256) is sent to a
  time-stamping authority (TSA). The signed token proves the log — and therefore every evidence hash,
  finding and report digest recorded before it — existed at that time. Stored next to the log:
    timestamp-<seq>.tsr   the TSA's DER response (verify: openssl ts -verify -digest <head> -in … -CAfile …)
    timestamp-<seq>.json  tsa, gen_time, covers_seq, head, token_sha256
  If the TSA cannot be reached the run still completes: a `timestamp_pending` entry is logged and
  `rv-hashinv timestamp <log-dir>` adds the timestamp later (logged as `timestamp_obtained`).

PDF signature
  Each PDF is signed with the examiner's own certificate (.p12/.pfx). The password is never logged.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import tsp

DEFAULT_TSA = "http://timestamp.digicert.com"
TIMEOUT_S = 15


class TimestampError(Exception):
    pass


@dataclass
class Timestamp:
    tsa: str
    gen_time: str
    covers_seq: int
    head: str
    token_sha256: str
    file: str

    def to_json(self) -> dict:
        return {
            "tsa": self.tsa,
            "gen_time": self.gen_time,
            "covers_seq": self.covers_seq,
            "head": self.head,
            "token_sha256": self.token_sha256,
            "file": self.file,
        }


def build_request(digest: bytes) -> tuple[bytes, int]:
    nonce = int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
            "nonce": nonce,
            "cert_req": True,
        }
    )
    return req.dump(), nonce


def parse_response(der: bytes, digest: bytes, nonce: int | None) -> tuple[str, bytes]:
    """Returns (gen_time ISO, token DER) or raises TimestampError."""
    resp = tsp.TimeStampResp.load(der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise TimestampError(f"TSA refused the request: {status}")
    token = resp["time_stamp_token"]
    info = token["content"]["encap_content_info"]["content"].parsed
    if info["message_imprint"]["hashed_message"].native != digest:
        raise TimestampError("the token does not cover the requested digest")
    if nonce is not None and info["nonce"].native not in (None, nonce):
        raise TimestampError("nonce mismatch (possible replay)")
    gen = info["gen_time"].native
    return gen.strftime("%Y-%m-%dT%H:%M:%SZ"), token.dump()


def request_timestamp(digest: bytes, url: str, timeout: float = TIMEOUT_S) -> tuple[str, bytes, bytes]:
    """(gen_time, token DER, full response DER)."""
    if not url.lower().startswith(("http://", "https://")):
        raise TimestampError(f"unsupported TSA URL scheme: {url}")
    body, nonce = build_request(digest)
    req = urllib.request.Request(  # noqa: S310 - http(s) only, checked above
        url, data=body, headers={"Content-Type": "application/timestamp-query"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - URL chosen by the examiner
            der = r.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise TimestampError(f"cannot reach {url}: {getattr(e, 'reason', e)}") from e
    gen, token = parse_response(der, digest, nonce)
    return gen, token, der


def timestamp_head(log_dir: Path, seq: int, head: str, url: str) -> Timestamp:
    gen, _token, der = request_timestamp(bytes.fromhex(head), url)
    name = f"timestamp-{seq:05d}.tsr"
    (log_dir / name).write_bytes(der)
    ts = Timestamp(url, gen, seq, head, hashlib.sha256(der).hexdigest(), name)
    (log_dir / f"timestamp-{seq:05d}.json").write_text(json.dumps(ts.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ts


def verify_timestamps(log_dir: Path, heads: dict[int, str]) -> list[str]:
    """Checks every timestamp-*.tsr: file digest as recorded, imprint == entry_hash of the covered entry."""
    problems = []
    for meta_path in sorted(log_dir.glob("timestamp-*.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        der = (log_dir / meta["file"]).read_bytes() if (log_dir / meta["file"]).exists() else b""
        if hashlib.sha256(der).hexdigest() != meta["token_sha256"]:
            problems.append(f"{meta['file']}: token file missing or altered")
            continue
        expected = heads.get(meta["covers_seq"])
        try:
            parse_response(der, bytes.fromhex(expected or "00" * 32), None)
        except (TimestampError, ValueError) as e:
            problems.append(f"{meta['file']}: {e} (entry #{meta['covers_seq']})")
    return problems


# ---------------------------------------------------------------- PDF signatures


@dataclass
class PdfSigner:
    signer: object
    subject: str
    fingerprint_sha256: str

    @classmethod
    def load(cls, pfx: Path, password: str | None) -> PdfSigner:
        from pyhanko.sign import signers

        try:
            s = signers.SimpleSigner.load_pkcs12(pfx_file=str(pfx), passphrase=password.encode() if password else None)
        except Exception as e:  # noqa: BLE001 - pyhanko raises several types
            raise ValueError(f"cannot load signing certificate {pfx}: {e}") from e
        if s is None:
            raise ValueError(f"cannot load signing certificate {pfx}: wrong password or unsupported file")
        cert = s.signing_cert
        return cls(s, cert.subject.human_friendly, hashlib.sha256(cert.dump()).hexdigest())

    def sign(self, pdf: bytes, reason: str, location: str = "") -> bytes:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers

        w = IncrementalPdfFileWriter(io.BytesIO(pdf))
        meta = signers.PdfSignatureMetadata(field_name="RakvorExaminerSignature", reason=reason, location=location or None)
        out = signers.sign_pdf(w, meta, signer=self.signer)
        return out.getvalue()
