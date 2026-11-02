import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture
def insecure():
    return json.loads((ROOT / "samples" / "insecure_account.json").read_text())


@pytest.fixture
def secure():
    return json.loads((ROOT / "samples" / "secure_account.json").read_text())
