"""RFC 3161 timestamps, PDF signatures and custody forms, against a local test TSA (tests/fake_tsa.py)."""

import http.server
import io
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import fake_tsa  # noqa: E402
from rv_hashinv.core import RunConfig, run  # noqa: E402
from rv_hashinv.core.audit import AuditLog, heads, verify  # noqa: E402
from rv_hashinv.core.trust import MAX_RESPONSE, TimestampError, request_timestamp, timestamp_head, verify_timestamps  # noqa: E402
from rv_hashinv.core.verify import verify_log  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    fake_tsa.make_certs(d)
    srv, url = fake_tsa.serve(d)
    yield d, url
    srv.shutdown()


def _run(tmp_path, sample, **kw):
    cfg = RunConfig(inputs=[sample], out_dir=tmp_path / "out", algorithms=["sha256", "blake3"], langs=["en"], actor="tester", **kw)
    return run(cfg, lambda e: None, threading.Event())


def test_timestamp_covers_chain_head_and_tamper_is_caught(tmp_path, sample, pki):
    _, url = pki
    s = _run(tmp_path, sample, tsa_url=url)
    assert s.timestamp["status"] == "ok"
    log = s.log_dir / "audit.jsonl"
    assert verify(log)[1] == []
    assert verify_timestamps(s.log_dir, heads(log)) == []
    meta = json.loads(next(s.log_dir.glob("timestamp-*.json")).read_text())
    assert heads(log)[meta["covers_seq"]] == meta["head"]
    v = verify_log(log)
    assert v.problems == [] and v.truncation == (
        f"truncation: entries up to #{meta['covers_seq']} are anchored by the RFC 3161 timestamp (timestamp-{meta['covers_seq']:05d}.json); "
        "3 entries after it (timestamp_obtained, statistics_report_written, run_finished) cannot be proven complete"
    )
    # Removing entries back to (and including) the timestamped one is detected through covers_seq.
    full = log.read_text("utf-8")
    log.write_text("".join(full.splitlines(keepends=True)[:-4]), encoding="utf-8")
    assert any(p.startswith(f"truncated: {meta['file']} covers entry #{meta['covers_seq']}") for p in verify_log(log).problems)
    log.write_text(full, encoding="utf-8")
    tsr = s.log_dir / meta["file"]
    tsr.write_bytes(tsr.read_bytes()[:-1] + b"\x00")
    assert verify_timestamps(s.log_dir, heads(log))
    assert verify_log(log).problems


def test_offline_tsa_is_pending_then_added_later(tmp_path, sample, pki):
    _, url = pki
    s = _run(tmp_path, sample, tsa_url="http://127.0.0.1:9/tsr")
    assert s.timestamp["status"] == "pending"
    assert '"timestamp_pending"' in (s.log_dir / "audit.jsonl").read_text()
    audit = AuditLog.resume(s.log_dir, "later")
    ts = timestamp_head(s.log_dir, audit.seq, audit.head, url)
    audit.record("timestamp_obtained", ts.file, ts.to_json())
    audit.close()
    log = s.log_dir / "audit.jsonl"
    assert verify(log)[1] == [] and verify_timestamps(s.log_dir, heads(log)) == []


def test_request_rejects_unreachable_tsa():
    with pytest.raises(TimestampError):
        request_timestamp(b"\0" * 32, "http://127.0.0.1:9/tsr", timeout=2)


def test_tsa_response_larger_than_1_mib_is_refused():
    class Huge(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(b"\x30" * (MAX_RESPONSE + 4096))

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Huge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(TimestampError, match="larger than 1048576 bytes"):
            request_timestamp(b"\0" * 32, f"http://127.0.0.1:{srv.server_address[1]}/tsr", timeout=5)
    finally:
        srv.shutdown()
    assert MAX_RESPONSE == 1 << 20


def test_every_pdf_is_signed_with_the_examiner_certificate(tmp_path, sample, pki):
    d, _ = pki
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    s = _run(tmp_path, sample, sign_cert=d / "examiner.p12", sign_password="test", jurisdiction="fr")
    pdfs = list(s.report_dir.rglob("*.pdf"))
    assert pdfs
    for p in pdfs:
        sig = PdfFileReader(io.BytesIO(p.read_bytes())).embedded_signatures
        assert sig, p.name
        st = validate_pdf_signature(sig[0])
        assert st.intact and st.valid, p.name
        assert "Ana Ruiz" in st.signing_cert.subject.human_friendly
    log = (s.log_dir / "audit.jsonl").read_text()
    assert '"signing_certificate_loaded"' in log and "password" not in log
    # The reports print the signer's certificate fingerprint, as logged at signing_certificate_loaded.
    fp = next(json.loads(x) for x in log.splitlines() if '"signing_certificate_loaded"' in x)["details"]["certificate_sha256"]
    assert len(fp) == 64
    item = next((s.report_dir / "items").iterdir())
    assert fp in (item / "technical.en.html").read_text("utf-8")
    assert json.loads((s.report_dir / "statistics.json").read_text("utf-8"))["run"]["pdf_signer_certificate_sha256"] == fp


def test_wrong_certificate_password_fails_and_is_audited(tmp_path, sample, pki):
    d, _ = pki
    with pytest.raises(ValueError):
        _run(tmp_path, sample, sign_cert=d / "examiner.p12", sign_password="wrong")
    log = next((tmp_path / "out" / "logs").iterdir()) / "audit.jsonl"
    assert '"run_failed"' in log.read_text()


@pytest.mark.parametrize("jurisdiction,lang,title", [("co", "es", "Registro de cadena de custodia"), ("fr", "fr", "Fiche de traçabilité")])
def test_custody_form_per_item_in_country_language_and_english(tmp_path, sample, jurisdiction, lang, title):
    s = _run(tmp_path, sample, jurisdiction=jurisdiction)
    for item in (s.report_dir / "items").iterdir():
        for f in ("custody.json", f"custody.{lang}.html", f"custody.{lang}.pdf", "custody.en.html", "custody.en.pdf"):
            assert (item / f).is_file(), f
        assert title in (item / f"custody.{lang}.html").read_text("utf-8")
        cj = json.loads((item / "custody.json").read_text())
        assert cj["schema"] == "rakvor.item-custody/1" and cj["jurisdiction"] == jurisdiction and len(cj["hashes"]) == 2
