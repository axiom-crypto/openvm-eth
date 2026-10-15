"""Proof ids must never escape JOBS_DIR. Run from the repo root: `python -m pytest server`."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from server import main

SCRIPT = Path(main.__file__).parent / "prove_block.sh"
VALID_IDS = ["prf_01k3w1spnpnxzry017g5jzcy97", "123E4567-e89b-12d3-a456-426614174000"]
INVALID_IDS = ["", "..", "a/b", "a.b", "-rf", "a" * 129, "prf_x\n", "../escape"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setattr(main, "JOBS", {})
    monkeypatch.setattr(main, "run_proof", lambda *_: MagicMock(pid=1))
    return TestClient(main.app)


def test_rejects_unsafe_ids(client, tmp_path):
    for proof_id in INVALID_IDS + [str(tmp_path / "escape")]:
        resp = client.post("/start_proof", json={"proof_uuid": proof_id})
        assert resp.status_code == 422, proof_id
        script = subprocess.run(
            ["bash", SCRIPT, proof_id], env={"JOBS_DIR": str(tmp_path / "jobs")}, capture_output=True
        )
        assert script.returncode == 2, proof_id
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("proof_id", VALID_IDS)
def test_keeps_valid_ids_verbatim(client, tmp_path, proof_id):
    resp = client.post("/start_proof", json={"proof_uuid": proof_id})
    assert resp.status_code == 202
    assert resp.json()["job_dir"] == str(tmp_path / "jobs" / proof_id)
