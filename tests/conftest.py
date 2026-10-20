import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("GROQ_API_KEY", "")
os.environ.setdefault("CACHE_ENABLED", "False")

import pytest


@pytest.fixture
def sample_log():
    return (
        "2024-03-15 08:31:05 ERROR [PaymentGateway] Connection timeout\n"
        "2024-03-15 08:35:10 ERROR [Database] Connection lost\n"
        "2024-03-15 08:40:35 SECURITY [AuthService] Brute force detected\n"
        "2024-03-15 08:45:35 FATAL [SystemMonitor] System crash\n"
        "2024-03-15 09:30:10 INFO [API] Request processed\n"
    )