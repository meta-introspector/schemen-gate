"""Observe acceptance through process exit from a parent without ML imports.

Raw logs remain private unless --acceptance-logs is explicitly selected. Receipts
are diagnostic records, not signatures or hostile-process containment evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import signal
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from .acceptance_environment import check_environment
else:
    from acceptance_environment import check_environment

Receipt = dict[str, object]


def write_receipt(path: Path, data: Receipt) -> None:
    temporary = path.with_suffix(".pending")
    with temporary.open("w") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def classify(returncode: int) -> Receipt:
    if returncode < 0:
        number = -returncode
        try:
            name = signal.Signals(number).name
        except ValueError:
            name = "UNKNOWN"
        crash = name in {"SIGSEGV", "SIGBUS", "SIGABRT", "SIGILL", "SIGFPE", "SIGTRAP"}
        return {
            "status": "NATIVE_CRASH" if crash else "SIGNALLED",
            "signal": number,
            "signal_name": name,
        }
    return {"status": "PASS" if returncode == 0 else "FAILED", "signal": None}


def group_exists(child: subprocess.Popen[bytes]) -> bool:
    if os.name != "posix":
        return child.poll() is None
    try:
        os.killpg(child.pid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_owned_processes(child: subprocess.Popen[bytes]) -> bool:
    """Stop only the new process group this observer created, then await quiescence."""
    try:
        if os.name == "posix":
            os.killpg(child.pid, signal.SIGKILL)
        elif child.poll() is None:
            child.kill()
    except ProcessLookupError:
        pass
    child.wait(timeout=5)
    deadline = time.monotonic() + 2
    while group_exists(child) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not group_exists(child)


def observe(command: list[str], directory: Path, cwd: Path, timeout: float) -> Receipt:
    if not command or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Provide a Python executable and a finite positive timeout")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = directory / "receipt.json"
    result: Receipt = {
        "schema": "sekos/native-process/v1",
        "status": "STARTING",
        "started_at": time.time(),
        "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
        "executable": command[0],
        "cwd": str(cwd),
    }
    write_receipt(receipt, result)
    env = {
        **os.environ,
        "PYTHONFAULTHANDLER": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    child: subprocess.Popen[bytes] | None = None
    try:
        environment = check_environment(command[0], env, cwd)
        result["environment"] = environment
        if not environment["isolated"]:
            result.update(
                status="ENVIRONMENT_REFUSED",
                reason="Use an isolated venv without external import roots",
            )
            return result
        with (
            (directory / "stdout.log").open("wb") as stdout,
            (directory / "stderr.log").open("wb") as stderr,
        ):
            child = subprocess.Popen(  # nosec B603
                command,
                cwd=cwd,
                env=env,
                stdout=stdout,
                stderr=stderr,
                start_new_session=os.name == "posix",
            )
            result.update(status="RUNNING", pid=child.pid)
            write_receipt(receipt, result)
            try:
                code = child.wait(timeout=timeout)
                result.update(classify(code), returncode=code)
                if group_exists(child):
                    if code == 0:
                        result["status"] = "DESCENDANTS_REMAINING"
                    result["termination_requested"] = True
                    result["cleanup_confirmed"] = stop_owned_processes(child)
                else:
                    result["cleanup_confirmed"] = True
            except subprocess.TimeoutExpired:
                result.update(status="TIMEOUT", termination_requested=True)
                result["cleanup_confirmed"] = stop_owned_processes(child)
                result["returncode"] = child.returncode
        if result.get("cleanup_confirmed", True):
            for name in ("stdout", "stderr"):
                digest = hashlib.sha256()
                with (directory / (name + ".log")).open("rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        digest.update(chunk)
                result[name + "_sha256"] = digest.hexdigest()
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        result.update(
            status="INTERRUPTED" if isinstance(exc, KeyboardInterrupt) else "OBSERVER_ERROR",
            error_type=type(exc).__name__,
        )
        if child is not None:
            result["termination_requested"] = True
            try:
                result["cleanup_confirmed"] = stop_owned_processes(child)
            except (OSError, subprocess.SubprocessError):
                result["cleanup_confirmed"] = False
    finally:
        result["finished_at"] = time.time()
        write_receipt(receipt, result)
    return result


def echo_logs(directory: Path) -> None:
    """Explicit opt-in for CI using reviewed, synthetic test data."""
    for name, output in (("stdout", sys.stdout), ("stderr", sys.stderr)):
        path = directory / (name + ".log")
        if path.exists():
            with path.open(encoding="utf-8", errors="replace") as stream:
                shutil.copyfileobj(stream, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt-dir", required=True, type=Path)
    parser.add_argument("--cwd", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--acceptance-logs", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("Provide a Python executable and a finite positive timeout")
    result = observe(command, args.receipt_dir, args.cwd, args.timeout)
    if args.acceptance_logs:
        echo_logs(args.receipt_dir)
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 1


def hardened_entry(main_function: Callable[[], int]) -> int:
    """Observe the entry point's exit. The child marker only prevents recursion."""
    marker = "--native-acceptance-child"
    if sys.argv[1:2] == [marker]:
        sys.argv.pop(1)
        return main_function()
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        return main_function()
    show_logs = "--acceptance-logs" in sys.argv[1:]
    arguments = [arg for arg in sys.argv[1:] if arg != "--acceptance-logs"]
    directory = Path(tempfile.mkdtemp(prefix="sekos-native-acceptance-")) / "run"
    result = observe(
        [sys.executable, str(Path(sys.argv[0]).resolve()), marker, *arguments],
        directory,
        Path.cwd(),
        3600,
    )
    if show_logs:
        echo_logs(directory)
    print(json.dumps({"status": result["status"], "receipt": str(directory / "receipt.json")}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
