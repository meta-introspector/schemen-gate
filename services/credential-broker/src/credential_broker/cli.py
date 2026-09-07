from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path

from .api import create_app
from .broker import Broker
from .models import identifier, token_hash
from .vault import FileKeyProvider, Vault


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def bootstrap(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    admin, agent = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    write_private(directory / "master.key", secrets.token_bytes(32))
    write_private(directory / "admin.token", admin.encode())
    write_private(directory / "agent.token", agent.encode())
    config = {
        "identities": {
            token_hash(admin): {"tenant": "local", "subject": "admin", "admin": True},
            token_hash(agent): {"tenant": "local", "subject": "agent", "admin": False},
        },
        "providers": {
            "github": {
                "origin": "https://api.github.com",
                "routes": [{"method": "GET", "path": "/user"}],
            }
        },
    }
    write_private(directory / "config.json", json.dumps(config, indent=2).encode() + b"\n")
    print(
        f"Created owner-only key, tokens, and configuration in {directory}. No secret values printed."
    )


def run() -> None:
    parser = argparse.ArgumentParser(description="Local credential store and constrained broker")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--secrets-dir", type=Path, required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--key-file", type=Path, required=True)
    serve.add_argument("--database", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8787)
    rekey = sub.add_parser("rekey", help="Offline transactional master-key rotation")
    rekey.add_argument("--database", type=Path, required=True)
    rekey.add_argument("--old-key-file", type=Path, required=True)
    rekey.add_argument("--new-key-file", type=Path, required=True)
    for name in ("store", "request", "revoke"):
        command = sub.add_parser(name)
        command.add_argument("--token-file", type=Path, required=True)
        command.add_argument("--connection", type=identifier, required=True)
        command.add_argument("--port", type=int, default=8787)
        if name == "store":
            command.add_argument("--provider", required=True)
            command.add_argument("--subject", action="append", required=True)
            command.add_argument("--credential-file", type=Path, required=True)
            command.add_argument("--expires-at", type=float)
        if name == "request":
            command.add_argument("--method", required=True)
            command.add_argument("--path", required=True)
            command.add_argument("--json-file", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    if args.command == "init":
        bootstrap(args.secrets_dir)
        return
    if args.command in {"store", "request", "revoke"}:
        from .client import call

        raise SystemExit(call(args))
    if args.command == "rekey":
        Vault(args.database, FileKeyProvider(args.old_key_file)).rekey(
            FileKeyProvider(args.new_key_file)
        )
        print("Vault re-encrypted transactionally. Restart with the new key file.")
        return
    from .config import load_config

    identities, providers = load_config(args.config)
    broker = Broker(Vault(args.database, FileKeyProvider(args.key_file)), providers)
    # httpx INFO logs full URLs. Keep all HTTP client logs off the secret-handling path.
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    import uvicorn

    uvicorn.run(
        create_app(broker, identities),
        host="127.0.0.1",
        port=args.port,
        access_log=False,
        proxy_headers=False,
        limit_concurrency=32,
        timeout_keep_alive=5,
        ws="none",
        h11_max_incomplete_event_size=16384,
    )


def main() -> None:
    try:
        run()
    except Exception:
        # Transport exceptions may embed authorization headers. Never print
        # exception text or tracebacks from this secret-handling command.
        print(
            "Broker operation failed; check protected inputs and service availability.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
