"""A stand-in for Oracle that answers the way the real one does, for the cases the tool must tell apart.

Not a SQL engine: it understands the one lookup query and the ALTER USER statement the tool sends,
and refuses anything else with ORA-00900, so a change in what the tool sends breaks the tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from oracle_password_rotate.db import DBError

ALTER = re.compile(r'ALTER USER "([^"]+)" IDENTIFIED BY "([^"]*)"(?: REPLACE "([^"]*)")?')
LOOKUP = re.compile(r"select username from dba_users where username in \((:n\d+(?:, :n\d+)*)\)")


@dataclass
class User:
    password: str
    admin: bool = False
    locked: bool = False
    create_session: bool = True
    failures: int = 0
    history: list[str] = field(default_factory=list)


class FakeDB:
    def __init__(self):
        self.users = {
            "SYSTEM": User("Admin-pass-0001", admin=True),
            "APP_SVC": User("Initial-pass-001"),
            "REPORT": User("Report-pass-0001"),
        }
        self.min_length = 12
        self.lock_after = 3
        self.down = False
        self.silent_no_save = False   # ALTER USER "succeeds", nothing changes
        self.store_other = False      # ALTER USER stores something else than asked
        self.statements: list[str] = []
        self.attempts: list[tuple[str, bool]] = []

    def connect(self, user: str, password: str, sysdba: bool = False):
        if self.down:
            raise DBError("DPY-6005", "DPY-6005: cannot connect to database")
        name = user[1:-1] if user.startswith('"') else user.upper()
        u = self.users.get(name)
        if u is not None and u.locked:
            # like Oracle 21c (checked in tests/test_oracle.py): the same answer for any password
            self.attempts.append((name, False))
            raise DBError("ORA-28000", "ORA-28000: The account is locked.")
        if u is None or u.password != password:
            if u is not None:
                u.failures += 1
                if u.failures >= self.lock_after:
                    u.locked = True
            self.attempts.append((name, False))
            raise DBError("ORA-01017", "ORA-01017: invalid credential or not authorized; logon denied")
        if not u.create_session:
            raise DBError("ORA-01045", "ORA-01045: Login denied. User lacks CREATE SESSION privilege.")
        u.failures = 0
        self.attempts.append((name, True))
        return FakeConn(self, name)


class FakeConn:
    def __init__(self, db: FakeDB, user: str):
        self.db, self.user = db, user

    def query(self, sql, params):
        m = LOOKUP.fullmatch(sql)
        if not m:
            raise DBError("ORA-00900", "ORA-00900: invalid SQL statement")
        if not self.db.users[self.user].admin:
            raise DBError("ORA-00942", "ORA-00942: table or view does not exist")
        return [(n,) for n in params.values() if n in self.db.users]

    def execute(self, sql):
        self.db.statements.append(sql)
        m = ALTER.fullmatch(sql)
        if not m:
            raise DBError("ORA-00900", "ORA-00900: invalid SQL statement")
        name, new, old = m.groups()
        db, me = self.db, self.db.users[self.user]
        u = db.users.get(name)
        if u is None:
            raise DBError("ORA-01918", f"ORA-01918: user '{name}' does not exist")
        if not me.admin:
            if name != self.user:
                raise DBError("ORA-01031", "ORA-01031: insufficient privileges")
            if old is None:
                raise DBError("ORA-28221", "ORA-28221: REPLACE not specified")
            if old != u.password:
                raise DBError("ORA-28008", "ORA-28008: invalid old password")
        if len(new) < db.min_length:
            raise DBError("ORA-28003", "ORA-28003: password verification for the specified password failed")
        if new in u.history or new == u.password:
            raise DBError("ORA-28007", "ORA-28007: the password cannot be reused")
        if db.silent_no_save:
            return
        u.history.append(u.password)
        u.password = new + "x" if db.store_other else new

    def close(self):
        pass
