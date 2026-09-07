"""The optional service must not become a dependency or member of core artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "services/credential-broker").is_dir():
    pytest.skip("broker is intentionally absent from core distributions", allow_module_level=True)


def test_service_excluded_from_core_sdist() -> None:
    from scripts.verify_dist import include_in_sdist

    for path in (ROOT / "services/credential-broker").rglob("*.py"):
        assert not include_in_sdist(path.relative_to(ROOT).as_posix())
    assert "prune services" in (ROOT / "MANIFEST.in").read_text()


def test_core_metadata_and_source_do_not_import_broker() -> None:
    project = (ROOT / "pyproject.toml").read_text()
    assert "credential-broker" not in project
    assert "fastapi" not in project and "uvicorn" not in project
    for path in (ROOT / "src/schemen_gate").glob("*.py"):
        assert "credential_broker" not in path.read_text()


def test_service_license_matches_repository_license() -> None:
    assert (ROOT / "services/credential-broker/LICENSE").read_bytes() == (
        ROOT / "LICENSE"
    ).read_bytes()
