"""Command line entry point. Progress to stderr, one result line to stdout, the cause in the exit code."""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import flow
from .db import Target, connect
from .names import BadValue, check_password
from .tunnel import Tunnel, TunnelError


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="oracle-password-rotate",
        description="Change an Oracle account's password, then sign in as that account to prove it.",
        epilog="Passwords are read from environment variables only; the process list shows every argument.",
    )
    p.add_argument("--host", required=True, help="database host, as seen from the SSH server when --ssh-tunnel is used")
    p.add_argument("--port", type=int, default=1521)
    p.add_argument("--service", required=True, help="service name, e.g. the PDB service (not a SID)")
    p.add_argument("--account", required=True, help="account whose password is changed")
    p.add_argument("--new-password-env", required=True, metavar="NAME")
    p.add_argument("--old-password-env", metavar="NAME",
                   help="current password: required in self mode, used to explain a failed verification")
    p.add_argument("--admin-user", help="sign in as this account to change it (admin mode). Omit for self mode")
    p.add_argument("--admin-password-env", metavar="NAME")
    p.add_argument("--sysdba", action="store_true", help="sign the admin in AS SYSDBA")
    p.add_argument("--no-diagnose", action="store_true",
                   help="never try the old password (each wrong attempt counts toward FAILED_LOGIN_ATTEMPTS)")
    p.add_argument("--ssh-tunnel", metavar="USER@HOST[:PORT]", help="reach the listener through SSH port forwarding")
    p.add_argument("--ssh-key", help="private key for the tunnel")
    p.add_argument("--ssh-password-env", metavar="NAME", help="SSH password for the tunnel")
    p.add_argument("--known-hosts", help="extra known_hosts file; unknown host keys are always refused")
    p.add_argument("--disable-oob", action="store_true",
                   help="turn off Oracle Net out-of-band breaks (needed through some tunnels and firewalls)")
    p.add_argument("--timeout", type=float, default=20.0, help="connect and per-call timeout in seconds")
    return p.parse_args(argv)


class UsageError(Exception):
    pass


def env(name: str | None, what: str, required: bool) -> str | None:
    if not name:
        if required:
            raise UsageError(f"{what}: missing option")
        return None
    value = os.environ.get(name)
    if not value:
        raise UsageError(f"{what}: environment variable {name} is not set or empty")
    return value


def redact(text: str, secrets) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "[redacted]")
    return text


def main(argv=None, connect_fn=None) -> int:
    args = parse_args(argv)
    secrets: list[str] = []

    def log(msg: str) -> None:
        print(f"{time.strftime('%H:%M:%S')} {redact(msg, secrets)}", file=sys.stderr, flush=True)

    def result(code: int, msg: str) -> int:
        print(redact("OK: " + msg if code == 0 else f"FAIL {code}: {msg}", secrets), flush=True)
        return code

    try:
        new = env(args.new_password_env, "new password", True)
        old = env(args.old_password_env, "old password", False)
        admin_pw = env(args.admin_password_env, "admin password", bool(args.admin_user))
        ssh_pw = env(args.ssh_password_env, "SSH password", False)
        secrets += [s for s in (new, old, admin_pw, ssh_pw) if s]
        if not args.admin_user and not old:
            raise UsageError("self mode (no --admin-user) needs --old-password-env")
        if args.admin_password_env and not args.admin_user:
            raise UsageError("--admin-password-env without --admin-user")
        if old is not None and old == new:
            raise UsageError("new password equals the old one; the verification could not tell them apart")
        check_password(new, "new password")  # before connecting: a password Oracle cannot take
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return flow.USAGE
    except BadValue as e:
        return result(flow.REJECTED, str(e))

    req = flow.Request(account=args.account, new_password=new, old_password=old, admin_user=args.admin_user,
                       admin_password=admin_pw, sysdba=args.sysdba, diagnose=not args.no_diagnose)

    def run(host: str, port: int) -> str:
        target = Target(host, port, args.service, args.timeout, args.disable_oob)
        fn = connect_fn or (lambda user, pw, sysdba: connect(target, user, pw, sysdba))
        log(f"start: {args.account} on {args.host}:{args.port}/{args.service}"
            f"{' via SSH ' + args.ssh_tunnel if args.ssh_tunnel else ''}{' (OOB off)' if args.disable_oob else ''}")
        return flow.rotate(fn, req, log)

    try:
        if not args.ssh_tunnel:
            return result(flow.OK, run(args.host, args.port))
        user, _, hostport = args.ssh_tunnel.rpartition("@")
        ssh_host, _, ssh_port = hostport.partition(":")
        if not user or not ssh_host:
            print("error: --ssh-tunnel must look like user@host[:port]", file=sys.stderr)
            return flow.USAGE
        with Tunnel(ssh_host, user, args.host, args.port, ssh_port=int(ssh_port or 22), password=ssh_pw,
                    key_file=args.ssh_key, known_hosts=args.known_hosts, timeout=args.timeout) as t:
            log(f"tunnel: 127.0.0.1:{t.local_port} -> {ssh_host} -> {args.host}:{args.port}")
            return result(flow.OK, run("127.0.0.1", t.local_port))
    except flow.Failure as e:
        return result(e.code, str(e))
    except TunnelError as e:
        return result(flow.UNREACHABLE, str(e))
    except Exception as e:  # report, never dump a traceback: frames may hold the statement text
        return result(1, f"unexpected {type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}")


if __name__ == "__main__":
    sys.exit(main())
