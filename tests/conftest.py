import os
import pathlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # GUI tests run without a display (CI)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample" / "evidence"


@pytest.fixture
def sample() -> pathlib.Path:
    return SAMPLE
