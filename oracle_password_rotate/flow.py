"""Change one account's password and prove it by signing in as that account.

    admin mode:  sign in as admin -> find the stored name -> ALTER USER ... IDENTIFIED BY
    self mode:   sign in as the account (old password) -> ALTER USER ... IDENTIFIED BY ... REPLACE
    then:        new session as the account with the NEW password
                 (if refused) with the OLD password, to tell "not changed" from "cannot sign in"

"ALTER USER succeeded" only says the statement ran. It does not say the account can sign in:
a locked account accepts a new password and stays locked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .db import DBError
from .names import SIMPLE, BadValue, alter_user_sql, candidates

OK = 0
USAGE = 2
SIGN_IN_FAILED = 10         # admin (or, in self mode, the account with its old password) refused
UNREACHABLE = 12            # listener, service name, network, tunnel
NOT_FOUND = 20
REJECTED = 21               # password policy: verify function, reuse rules, invalid old password
NOT_PERMITTED = 22
ALTER_FAILED = 23
NOT_CHANGED = 30            # the old password still signs in
BOTH_REFUSED = 31
UNVERIFIED = 32             # new password refused, old one deliberately not tried
CANNOT_SIGN_IN = 33         # changed, but the database refuses the session: locked, expired, no CREATE SESSION
TIMEOUT = 41

POLICY = {"ORA-28003", "ORA-28007", "ORA-28008", "ORA-28221", "ORA-28219"}
BAD_LOGIN = {"ORA-01017", "ORA-01005"}
SESSION_REFUSED = {
    "ORA-28000": "account is locked",
    "ORA-28001": "password has expired",
    "ORA-01045": "account lacks CREATE SESSION",
    "ORA-28009": "SYS must sign in as SYSDBA",
}
TIMEOUTS = {"DPY-4011", "DPY-4024", "ORA-03136"}


class Failure(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def is_network(code: str) -> bool:
    return code.startswith("DPY-6") or code.startswith("ORA-125") or code.startswith("ORA-121") \
        or code in {"ORA-03113", "ORA-03135", "ORA-12569"}


@dataclass
class Request:
    account: str
    new_password: str
    old_password: str | None
    admin_user: str | None
    admin_password: str | None
    sysdba: bool = False
    diagnose: bool = True


def _sign_in(connect: Callable, user: str, password: str, sysdba: bool, who: str):
    try:
        return connect(user, password, sysdba)
    except DBError as e:
        if e.code in TIMEOUTS:
            raise Failure(TIMEOUT, f"{who} sign-in timed out: {e}") from None
        if is_network(e.code):
            raise Failure(UNREACHABLE, f"cannot reach the database: {e}") from None
        raise Failure(SIGN_IN_FAILED, f"{who} sign-in refused: {e}") from None


def _stored_name(conn, account: str) -> str:
    """Exactly one stored name, or stop. 'scott' may mean SCOTT, or a quoted "scott", or both exist."""
    names = candidates(account)
    binds = {f"n{i}": n for i, n in enumerate(names)}
    sql = "select username from dba_users where username in (" + ", ".join(f":{k}" for k in binds) + ")"
    try:
        rows = [r[0] for r in conn.query(sql, binds)]
    except DBError as e:
        if e.code == "ORA-00942":
            raise Failure(NOT_PERMITTED, "admin cannot read DBA_USERS to look the account up") from None
        raise
    if not rows:
        raise Failure(NOT_FOUND, f"account {account!r} does not exist")
    if len(rows) > 1:
        raise Failure(NOT_FOUND, f"{account!r} matches {len(rows)} accounts ({', '.join(sorted(rows))}); "
                                 "give the exact name")
    return rows[0]


def login_name(stored: str) -> str:
    """A user name for signing in: upper-case simple names as they are, anything else quoted."""
    return stored if SIMPLE.fullmatch(stored) and stored == stored.upper() else f'"{stored}"'


def _try(connect, user, password) -> tuple[bool, DBError | None]:
    try:
        connect(user, password, False).close()
        return True, None
    except DBError as e:
        return False, e


def rotate(connect: Callable, req: Request, log: Callable[[str], None]) -> str:
    admin_mode = req.admin_user is not None
    # 1) sign in and change
    if admin_mode:
        conn = _sign_in(connect, req.admin_user, req.admin_password, req.sysdba, "admin")
        log(f"admin sign-in: ok ({req.admin_user}{' as SYSDBA' if req.sysdba else ''})")
    else:
        conn = _sign_in(connect, req.account, req.old_password, False, "account (old password)")
        log("account sign-in with the old password: ok (self mode, REPLACE clause)")
    try:
        name = _stored_name(conn, req.account) if admin_mode else candidates(req.account)[0]
        if admin_mode and name != req.account:
            log(f"account {req.account!r} is stored as {name!r}")
        sql = alter_user_sql(name, req.new_password, None if admin_mode else req.old_password)
        try:
            conn.execute(sql)
        except DBError as e:
            if e.code in POLICY or e.code.startswith("ORA-20"):
                raise Failure(REJECTED, f"password refused by the database: {e}") from None
            if e.code == "ORA-01918":
                raise Failure(NOT_FOUND, f"account {name!r} does not exist") from None
            if e.code == "ORA-01031":
                raise Failure(NOT_PERMITTED, f"not allowed to change {name!r}: {e}") from None
            if e.code in TIMEOUTS:
                raise Failure(TIMEOUT, f"ALTER USER timed out: {e}") from None
            raise Failure(ALTER_FAILED, f"ALTER USER failed: {e}") from None
        log(f"ALTER USER {name}: ok")
    except BadValue as e:
        raise Failure(REJECTED if "password" in str(e) else USAGE, str(e)) from None
    finally:
        conn.close()

    # 2) verify with a separate session as the account itself
    login = login_name(name)
    ok, err = _try(connect, login, req.new_password)
    if ok:
        log("verify: new password signs in")
        return f"password of {name} changed and verified"
    if err.code in SESSION_REFUSED:
        # ALTER USER went through, but the database refuses the session before it looks at the password
        # (a locked account answers ORA-28000 to a wrong password too), so the new one is not verified.
        raise Failure(CANNOT_SIGN_IN, f"ALTER USER succeeded, but {name} cannot sign in: "
                                      f"{SESSION_REFUSED[err.code]} ({err.code}); new password not verified")
    if is_network(err.code) or err.code in TIMEOUTS:
        raise Failure(UNREACHABLE, f"password changed, but the verification could not connect: {err}")
    log(f"verify: new password refused ({err.code})")

    # 3) why? Each wrong attempt counts toward FAILED_LOGIN_ATTEMPTS; --no-diagnose skips this one.
    if not req.diagnose or not req.old_password:
        raise Failure(UNVERIFIED, f"new password does not sign in ({err.code}); old password not tried")
    old_ok, old_err = _try(connect, login, req.old_password)
    if old_ok:
        raise Failure(NOT_CHANGED, "password was not changed: the old password still signs in")
    raise Failure(BOTH_REFUSED, f"neither the new nor the old password signs in ({err.code} / {old_err.code})")
