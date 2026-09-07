"""Owner-controlled, strict startup configuration."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .api import strict_object
from .models import Principal, ProviderPolicy, Route, identifier


def load_config(path: Path) -> tuple[dict[str, Principal], dict[str, ProviderPolicy]]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("configuration must be an owner-only regular file")
        raw = handle.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("configuration too large")
    config = strict_object(raw)
    if set(config) != {"identities", "providers"} or not config["identities"]:
        raise ValueError("configuration requires identities and providers")
    identities = {}
    for digest, data in config["identities"].items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("identity must be a SHA-256 token hash")
        identities[digest] = Principal(**data)
    providers = {}
    for name, data in config["providers"].items():
        identifier(name)
        providers[name] = ProviderPolicy(
            **{**data, "routes": tuple(Route(**r) for r in data["routes"])}
        )
        if providers[name].allow_loopback_http:
            raise ValueError("CLI service requires HTTPS providers; HTTP loopback is test-only")
    return identities, providers
