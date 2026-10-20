import os
import pathlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # GUI tests run without a display (CI)
os.environ.setdefault("RV_NO_TIMESTAMP", "1")  # CLI tests stay offline; tests/test_trust.py uses a local test TSA

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample" / "evidence"


@pytest.fixture
def sample() -> pathlib.Path:
    return SAMPLE
