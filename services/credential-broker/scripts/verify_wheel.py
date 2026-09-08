"""Verify the separately built broker wheel against this source tree."""

from __future__ import annotations

import hashlib
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    dist_info = f"schemen_credential_broker-{version}.dist-info"
    archive = ROOT / "dist" / f"schemen_credential_broker-{version}-py3-none-any.whl"
    sources = {p.relative_to(ROOT / "src").as_posix(): p for p in (ROOT / "src").rglob("*.py")}
    metadata_files = {
        f"{dist_info}/{name}"
        for name in (
            "METADATA",
            "WHEEL",
            "RECORD",
            "entry_points.txt",
            "top_level.txt",
            "licenses/LICENSE",
        )
    }
    with zipfile.ZipFile(archive) as wheel:
        names = wheel.namelist()
        assert len(names) == len(set(names)), "duplicate wheel members"
        assert set(names) == set(sources) | metadata_files, "unexpected wheel contents"
        for name, path in sources.items():
            assert wheel.read(name) == path.read_bytes(), f"source mismatch: {name}"
        assert wheel.read(f"{dist_info}/licenses/LICENSE") == (ROOT / "LICENSE").read_bytes()
        metadata = BytesParser().parsebytes(wheel.read(f"{dist_info}/METADATA"))
        assert metadata["Name"] == "schemen-credential-broker"
        assert metadata["Version"] == version
        assert metadata["Requires-Python"] == ">=3.11"
        assert (
            "schemen-broker = credential_broker.cli:main"
            in wheel.read(f"{dist_info}/entry_points.txt").decode()
        )
    print(
        f"Broker wheel: exact source, package boundary and license passed; sha256={hashlib.sha256(archive.read_bytes()).hexdigest()}"
    )


if __name__ == "__main__":
    main()
