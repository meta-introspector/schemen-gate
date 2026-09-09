"""Acceptance must observe process exit, not passing text."""

import hashlib
import json
import os
import signal
import sys
import time

import pytest

from scripts import native_acceptance as module
from scripts.acceptance_environment import check_environment


def test_signal_classification():
    assert module.classify(-11)["status"] == "NATIVE_CRASH"
    assert module.classify(-11)["signal_name"] == "SIGSEGV"
    assert module.classify(139)["status"] == "FAILED"  # shell encoding isn't proof
    assert module.classify(0)["status"] == "PASS"


def test_pass_text_then_signal_is_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "check_environment", lambda *a: {"isolated": True})
    result = module.observe(
        [
            sys.executable,
            "-c",
            'import os,signal; print("100 tests passed",flush=True); os.kill(os.getpid(),signal.SIGTERM)',
        ],
        tmp_path / "run",
        tmp_path,
        10,
    )
    assert result["status"] == "SIGNALLED"
    assert result["signal"] == signal.SIGTERM
    assert (tmp_path / "run" / "receipt.json").exists()


def test_reject_polluted_environment_before_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "check_environment", lambda *a: {"isolated": False})
    result = module.observe(
        [sys.executable, "-c", "raise AssertionError()"], tmp_path / "run", tmp_path, 10
    )
    assert result["status"] == "ENVIRONMENT_REFUSED"
    assert "pid" not in result


def test_timeout_not_mislabeled_as_native_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "check_environment", lambda *a: {"isolated": True})
    result = module.observe(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        tmp_path / "run",
        tmp_path,
        0.1,
    )
    assert result["status"] == "TIMEOUT"
    assert result["termination_requested"]


def test_success_and_unique_receipt_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "check_environment", lambda *a: {"isolated": True})
    directory = tmp_path / "run"
    assert (
        module.observe([sys.executable, "-c", 'print("ok")'], directory, tmp_path, 10)["status"]
        == "PASS"
    )
    with pytest.raises(FileExistsError):
        module.observe([sys.executable, "-c", "pass"], directory, tmp_path, 10)


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_timeout_must_be_finite_positive(tmp_path, timeout):
    with pytest.raises(ValueError, match="finite positive"):
        module.observe([sys.executable, "-c", "pass"], tmp_path / "run", tmp_path, timeout)
    assert not (tmp_path / "run").exists()


def test_external_import_root_is_refused(tmp_path):
    foreign = tmp_path / "foreign-lib"
    foreign.mkdir()
    work = tmp_path / "checkout"
    work.mkdir()
    result = check_environment(sys.executable, {**os.environ, "PYTHONPATH": str(foreign)}, work)
    assert not result["isolated"]
    assert str(foreign) in result["refused_paths"]


@pytest.mark.skipif(os.name != "posix", reason="Process-group supervision requires POSIX")
@pytest.mark.parametrize("parent_sleeps", [False, True])
def test_descendants_cannot_outlive_terminal_receipt(tmp_path, monkeypatch, parent_sleeps):
    monkeypatch.setattr(module, "check_environment", lambda *a: {"isolated": True})
    marker = tmp_path / "escaped.txt"
    worker = "import time,pathlib; time.sleep(1); pathlib.Path(%r).write_text('escaped')" % str(
        marker
    )
    parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); " % worker
    parent += "time.sleep(20)" if parent_sleeps else "print('PASS',flush=True)"
    directory = tmp_path / "run"
    result = module.observe([sys.executable, "-c", parent], directory, tmp_path, 0.3)
    assert result["status"] == ("TIMEOUT" if parent_sleeps else "DESCENDANTS_REMAINING")
    time.sleep(1.1)
    assert not marker.exists()
    stored = json.loads((directory / "receipt.json").read_text())
    assert stored["status"] == result["status"]
    if result["cleanup_confirmed"]:
        for name in ("stdout", "stderr"):
            assert (
                stored[name + "_sha256"]
                == hashlib.sha256((directory / (name + ".log")).read_bytes()).hexdigest()
            )
    else:
        assert "stdout_sha256" not in stored


def test_script_module_help_does_not_require_native_environment():
    import subprocess

    for target in ("scripts.check_native", "scripts.release_check"):
        result = subprocess.run(
            [sys.executable, "-m", target, "--help"], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout
