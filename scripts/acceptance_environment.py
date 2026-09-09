"""Check the interpreter and import roots before native acceptance starts."""

from __future__ import annotations

import json
import subprocess  # nosec B404
from pathlib import Path
from typing import TypedDict


class EnvironmentInfo(TypedDict):
    isolated: bool
    prefix: str
    refused_paths: list[str]


def check_environment(python: str, env: dict[str, str], cwd: Path) -> EnvironmentInfo:
    """Allow an isolated venv, its standard library, and the declared source root."""
    probe = subprocess.run(  # nosec B603
        [
            python,
            "-c",
            (
                "import sys,json,sysconfig; "
                "print(json.dumps(dict(prefix=sys.prefix,base=sys.base_prefix,paths=sys.path,"
                "stdlib=sysconfig.get_path('stdlib'),platstdlib=sysconfig.get_path('platstdlib'),"
                "zipname='python%d%d.zip' % sys.version_info[:2])))"
            ),
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    observed = json.loads(probe.stdout)
    names = ("prefix", "base", "stdlib", "platstdlib", "zipname")
    if (
        not isinstance(observed, dict)
        or any(not isinstance(observed.get(name), str) for name in names)
        or not isinstance(observed.get("paths"), list)
        or any(not isinstance(path, str) for path in observed["paths"])
    ):
        raise ValueError("Interpreter probe returned an invalid environment")
    root = Path(observed["prefix"]).resolve()
    cfg = root / "pyvenv.cfg"
    isolated = observed["prefix"] != observed["base"] and cfg.is_file()
    if isolated:
        fields = dict(line.split("=", 1) for line in cfg.read_text().splitlines() if "=" in line)
        isolated = {k.strip().lower(): v.strip().lower() for k, v in fields.items()}.get(
            "include-system-site-packages"
        ) == "false"
    libraries = {Path(observed[name]).resolve() for name in ("stdlib", "platstdlib")}
    archives = {path.parent / observed["zipname"] for path in libraries}
    source_roots = {cwd.resolve(), (cwd / "src").resolve(), (cwd / "scripts").resolve()}
    refused = []
    for entry in observed["paths"]:
        path = (Path(entry) if entry else cwd).resolve()
        if path.is_relative_to(root):
            continue
        external_package = "site-packages" in path.parts or "dist-packages" in path.parts
        allowed = (
            path in source_roots
            or path in archives
            or any(path.is_relative_to(library) for library in libraries)
        )
        if external_package or not allowed:
            refused.append(str(path))
    return {"isolated": isolated and not refused, "prefix": str(root), "refused_paths": refused}
