"""Local CLI client: read secrets from owner-only files, never argv."""

from __future__ import annotations

import json
import os
import re
import stat
from argparse import Namespace
from pathlib import Path

import httpx


def read_secret(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("secret file must be owner-only and owned by this user")
        value = handle.read(8194)
    if len(value) > 8193:
        raise ValueError("secret file too large")
    return value.decode().rstrip("\n")


def call(args: Namespace) -> int:
    token = read_secret(args.token_file)
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("invalid broker token file")
    headers = {"Authorization": "Bearer " + token}
    path = "/v1/connections/" + args.connection
    with httpx.Client(
        base_url=f"http://127.0.0.1:{args.port}",
        trust_env=False,
        follow_redirects=False,
        timeout=35,
    ) as client:
        if args.command == "store":
            data = {
                "provider": args.provider,
                "subjects": args.subject,
                "credential": read_secret(args.credential_file),
                "expires_at": args.expires_at,
            }
            response = client.put(path, headers=headers, json=data)
        elif args.command == "revoke":
            response = client.delete(path, headers=headers)
        else:
            data = {"method": args.method, "path": args.path}
            if args.json_file:
                data["json"] = json.loads(args.json_file.read_text())
            response = client.post(path + "/request", headers=headers, json=data)
    output = response.text if response.content else f"HTTP {response.status_code}"
    # Provider output is untrusted terminal content (OSC/CSI sequences, C1 controls).
    print("".join(ch if ch in "\n\t" or ch.isprintable() else f"\\u{ord(ch):04x}" for ch in output))
    return 0 if response.is_success else 1
