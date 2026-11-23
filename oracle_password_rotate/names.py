"""Account names and passwords on their way into an ALTER USER statement.

DDL takes no bind variables, so ALTER USER has to be built as text. Two rules keep that safe:
the account name is always a quoted identifier holding a name read back from the database, and a
password that could end the quoted string is refused before anything is sent.
"""

from __future__ import annotations

import re

# An unquoted Oracle identifier. Oracle stores these in upper case.
SIMPLE = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*")
MAX_NAME_BYTES = 128
MAX_PASSWORD_BYTES = 1024


class BadValue(ValueError):
    pass


def candidates(name: str) -> list[str]:
    """Stored names this input may refer to: scott -> SCOTT, a quoted-style "Mixed" stays as is."""
    if not name or '"' in name or "\0" in name or len(name.encode()) > MAX_NAME_BYTES:
        raise BadValue("account name is empty, too long, or contains a double quote")
    if SIMPLE.fullmatch(name) and name.upper() != name:
        return [name.upper(), name]
    return [name]


def quote_identifier(name: str) -> str:
    if not name or '"' in name or "\0" in name:
        raise BadValue("not a valid identifier")
    return '"' + name + '"'


def check_password(pw: str, what: str = "password") -> None:
    if not pw:
        raise BadValue(f"{what} is empty")
    if '"' in pw:
        # it would close the quoted string; Oracle does not allow it in passwords anyway
        raise BadValue(f"{what} contains a double quote, which an Oracle password cannot hold")
    if any(ord(c) < 32 or ord(c) == 127 for c in pw):
        raise BadValue(f"{what} contains a control character")
    if len(pw.encode()) > MAX_PASSWORD_BYTES:
        raise BadValue(f"{what} is longer than {MAX_PASSWORD_BYTES} bytes")


def alter_user_sql(stored_name: str, new: str, old: str | None = None) -> str:
    """The statement text. Never log it: it holds the password."""
    check_password(new, "new password")
    sql = f'ALTER USER {quote_identifier(stored_name)} IDENTIFIED BY "{new}"'
    if old is not None:
        check_password(old, "old password")
        sql += f' REPLACE "{old}"'
    return sql
