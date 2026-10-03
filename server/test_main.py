"""Proof id validation in the proving server and its wrapper script.

Run from the repo root: `python -m pytest server`.
"""

import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server import main

SCRIPT = Path(main.__file__).parent / "prove_block.sh"

VALID_IDS = [
    "prf_01k3w1spnpnxzry017g5jzcy97",
    "123e4567-e89b-12d3-a456-426614174000",
    "123E4567-E89B-12D3-A456-426614174000",
    "a" * 128,
]

INVALID_IDS = [
    "",
    ".",
    "..",
    "a/b",
    "a.b",
    "a b",
    "-rf",
    "a" * 129,
    "prf_01k3w1spnpnxzry017g5jzcy97\n",
    "\nprf_01k3w1spnpnxzry017g5jzcy97",
    "prf_é",
]

# Relative to `JOBS_DIR = tmp_path / "jobs"`, each of these resolves to `tmp_path / "escape"`.
ESCAPING_IDS = ["../escape", "x/../../escape", "{escape}"]


def escaping_ids(tmp_path: Path) -> list[str]:
    return [i.format(escape=tmp_path / "escape") for i in ESCAPING_IDS]


class FakePopen:
    def __init__(self, args, **_kwargs):
        self.args = args
        self.pid = 1

    def poll(self):
        return None


@pytest.fixture
def jobs_dir(tmp_path, monkeypatch):
    jobs = tmp_path / "jobs"
    monkeypatch.setenv("JOBS_DIR", str(jobs))
    return jobs


@pytest.fixture
def launched(monkeypatch):
    """Replaces the prover launch and records the argv of every job started."""
    calls = []

    def popen(args, **kwargs):
        calls.append(args)
        return FakePopen(args, **kwargs)

    monkeypatch.setattr(main.subprocess, "Popen", popen)
    monkeypatch.setattr(main, "JOBS", {})
    return calls


@pytest.fixture
def client():
    return TestClient(main.app)


def test_start_proof_rejects_invalid_ids(client, jobs_dir, launched, tmp_path):
    for proof_id in INVALID_IDS + escaping_ids(tmp_path) + [123, None, ["a"]]:
        resp = client.post("/start_proof", json={"proof_uuid": proof_id})
        assert resp.status_code == 422, proof_id

    assert launched == []
    assert not jobs_dir.exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("proof_id", VALID_IDS)
def test_start_proof_keeps_valid_id_verbatim(client, jobs_dir, launched, proof_id):
    resp = client.post("/start_proof", json={"proof_uuid": proof_id})

    assert resp.status_code == 202
    assert resp.json()["job_dir"] == str(jobs_dir / proof_id)
    assert (jobs_dir / proof_id).is_dir()
    assert launched == [[str(SCRIPT), proof_id]]


def test_status_routes_reject_invalid_ids(client, launched, tmp_path):
    for proof_id in INVALID_IDS + escaping_ids(tmp_path):
        assert client.get("/logs", params={"proof_uuid": proof_id}).status_code == 422, proof_id
    assert client.get("/proof_state/a.b").status_code == 422
    assert client.get("/proof_state/prf_x%0A").status_code == 422

    assert client.get("/logs", params={"proof_uuid": VALID_IDS[0]}).status_code == 404
    assert client.get(f"/proof_state/{VALID_IDS[0]}").status_code == 404


def run_script(tmp_path: Path, proof_id: str) -> subprocess.CompletedProcess:
    """Runs prove_block.sh with stub prover and s5cmd binaries that leave a marker if invoked."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name in ["prover", "s5cmd"]:
        stub = bin_dir / name
        stub.write_text(f'#!/bin/sh\ntouch "{tmp_path}/{name}-ran"\nexit 1\n')
        stub.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "JOBS_DIR": str(tmp_path / "jobs"),
        "OVM_BIN": str(bin_dir / "prover"),
    }
    return subprocess.run(["bash", str(SCRIPT), proof_id], env=env, capture_output=True, text=True)


def test_script_rejects_invalid_ids_before_side_effects(tmp_path):
    for proof_id in INVALID_IDS + escaping_ids(tmp_path):
        result = run_script(tmp_path, proof_id)
        assert result.returncode == 2, (proof_id, result.stderr)

    assert not (tmp_path / "jobs").exists()
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "s5cmd-ran").exists()
    assert not (tmp_path / "prover-ran").exists()


def test_script_accepts_valid_id(tmp_path):
    proof_id = VALID_IDS[0]
    result = run_script(tmp_path, proof_id)

    # Validation passes, the job dir is created, and the (stubbed) S3 download is attempted.
    assert (tmp_path / "jobs" / proof_id).is_dir(), result.stderr
    assert (tmp_path / "s5cmd-ran").exists()
