"""cvault command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .storage import make_backend
from .vault import Vault


def _vault(args) -> Vault:
    home = Path(args.home).expanduser()
    return Vault(home, make_backend(args.backend, home / "store"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvault", description="Encrypted, verifiable backups to Filecoin")
    p.add_argument("--home", default=os.environ.get("CVAULT_HOME", "~/.cumulus-vault"))
    p.add_argument("--backend", choices=["local", "lighthouse"], default=os.environ.get("CVAULT_BACKEND", "local"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create a vault and encryption key")
    b = sub.add_parser("backup", help="encrypt and store a file or folder")
    b.add_argument("path")
    b.add_argument("--label")
    r = sub.add_parser("restore", help="restore a backup")
    r.add_argument("dest")
    r.add_argument("--seq", type=int)
    v = sub.add_parser("verify", help="check the ledger and test-restore a backup")
    v.add_argument("--seq", type=int)
    sub.add_parser("log", help="show the backup ledger")
    args = p.parse_args(argv)

    try:
        vault = _vault(args)
        if args.cmd == "init":
            print(f"Key created at {vault.init()} - keep an offline copy; without it backups cannot be restored.")
        elif args.cmd == "backup":
            e = vault.backup(Path(args.path), args.label)
            print(f"Backup #{e['seq']} stored on {e['backend']}: {e['ref']}")
        elif args.cmd == "restore":
            e = vault.restore(Path(args.dest), args.seq)
            print(f"Restored backup #{e['seq']} to {args.dest}")
        elif args.cmd == "verify":
            res = vault.verify(args.seq)
            print(json.dumps(res, indent=2))
            return 0 if res["ledger_ok"] and res.get("restore_ok") else 2
        elif args.cmd == "log":
            for e in vault.ledger.entries():
                print(json.dumps(e, sort_keys=True))
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
