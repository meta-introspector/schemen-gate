"""Protected-file CLI for approving and executing a single Calendar operation."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import httpx

from .calendar import calendar_request
from .call_receipt import verify_receipt
from .client import read_secret
from .json_codec import strict_object
from .models import canonical, identifier

MAX_DOCUMENT = 65_536


def add_commands(subparsers: argparse._SubParsersAction[Any]) -> None:
    for name in ("calendar-approve", "calendar-execute"):
        command = subparsers.add_parser(name)
        command.add_argument("--port", type=int, default=8787)
        command.add_argument("--token-file", type=Path, required=True)
        command.add_argument("--grant-file", type=Path, required=True)
        if name == "calendar-approve":
            command.add_argument("--credential-file", type=Path, required=True)
            command.add_argument("--subject", required=True)
            command.add_argument("--channel", required=True)
            command.add_argument("--call-file", type=Path, required=True)
            command.add_argument("--expires-in", type=int, default=60)


def _read_document(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("document must be an owner-only regular file")
        raw = handle.read(MAX_DOCUMENT + 1)
    if len(raw) > MAX_DOCUMENT:
        raise ValueError("document too large")
    return strict_object(raw)


def _post(
    client: httpx.Client, token: str, path: str, data: dict[str, Any], *, expected_status: int
) -> dict[str, Any]:
    with client.stream(
        "POST", path, headers={"Authorization": "Bearer " + token}, json=data
    ) as response:
        if response.status_code != expected_status:
            raise ValueError("calendar operation was not accepted")
        raw = bytearray()
        for chunk in response.iter_bytes():
            if len(raw) + len(chunk) > MAX_DOCUMENT:
                raise ValueError("calendar response too large")
            raw.extend(chunk)
    return strict_object(bytes(raw))


def _grant(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"grant_id", "gate", "call", "aad_sha256", "receipt_key"}:
        raise ValueError("invalid grant document")
    identifier(value["grant_id"])
    if not isinstance(value["gate"], dict):
        raise ValueError("invalid grant document")
    for field in ("aad_sha256", "receipt_key"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise ValueError("invalid grant document")
    calendar_request(value["call"])
    return value


def _approve(args: argparse.Namespace, client: httpx.Client, token: str) -> int:
    call = _read_document(args.call_file)
    calendar_request(call)
    data = {
        "subject": identifier(args.subject),
        "channel": identifier(args.channel),
        "credential": read_secret(args.credential_file),
        "expires_in": args.expires_in,
        "call": call,
    }
    # Reserve before minting authority: existing files must not cause abandoned
    # approvals or overwrite an earlier approval. O_EXCL also rejects symlinks.
    fd = os.open(args.grant_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            grant = _grant(_post(client, token, "/v1/calendar-calls", data, expected_status=201))
            if canonical(grant["call"]) != canonical(call):
                raise ValueError("approval response changed the proposed call")
            raw = canonical(grant) + b"\n"
            if len(raw) > MAX_DOCUMENT:
                raise ValueError("approval document too large")
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        args.grant_file.unlink(missing_ok=True)
        raise
    print(grant["grant_id"])
    return 0


def _execute(args: argparse.Namespace, client: httpx.Client, token: str) -> int:
    grant = _grant(_read_document(args.grant_file))
    result = _post(
        client,
        token,
        f"/v1/calendar-calls/{grant['grant_id']}/execute",
        {"gate": grant["gate"], "call": grant["call"]},
        expected_status=200,
    )
    receipt = result.get("receipt")
    if not isinstance(receipt, dict):
        raise ValueError("calendar receipt missing")
    body = verify_receipt(receipt, grant["receipt_key"], grant["grant_id"], grant["aad_sha256"])
    event_id = grant["call"]["event"]["id"]
    if (
        result.get("event_id") != event_id
        or body.get("event_id") != event_id
        or result.get("provider_status") != body["provider_status"]
    ):
        raise ValueError("calendar response does not match its receipt")
    # The protected approval file comes from the administrator. Its pinned key
    # authenticates the receipt; arbitrary HTTP/provider error text is not output.
    print(json.dumps({"event_id": event_id, "outcome": body["outcome"], "receipt": receipt}))
    return 0 if body["outcome"] == "confirmed" else 1


def run(args: argparse.Namespace) -> int:
    if type(args.port) is not int or not 1 <= args.port <= 65535:
        raise ValueError("invalid local port")
    token = read_secret(args.token_file)
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token) is None:
        raise ValueError("invalid broker token file")
    with httpx.Client(
        base_url=f"http://127.0.0.1:{args.port}",
        trust_env=False,
        follow_redirects=False,
        timeout=35,
    ) as client:
        if args.command == "calendar-approve":
            return _approve(args, client, token)
        if args.command == "calendar-execute":
            return _execute(args, client, token)
    raise ValueError("unsupported calendar command")
