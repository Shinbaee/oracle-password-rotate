"""The only module that imports oracledb. Everything else talks to a `connect` function that
returns an object with `query()` and `execute()` and raises DBError, so the flow can be tested
against a fake database."""

from __future__ import annotations

from dataclasses import dataclass


class DBError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code  # "ORA-28003", "DPY-6005", ...


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    service: str
    timeout: float = 20.0
    disable_oob: bool = False

    @property
    def dsn(self) -> str:
        return f"{self.host}:{self.port}/{self.service}"


def _wrap(e) -> DBError:
    err = e.args[0] if e.args else None
    code = getattr(err, "full_code", "") or type(e).__name__
    text = str(err if err is not None else e).splitlines()[0] if str(e) else code
    return DBError(code, text)


class Connection:
    def __init__(self, conn):
        self._conn = conn

    def query(self, sql: str, params: dict) -> list[tuple]:
        import oracledb
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        except oracledb.Error as e:
            raise _wrap(e) from None

    def execute(self, sql: str) -> None:
        import oracledb
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql)
        except oracledb.Error as e:
            raise _wrap(e) from None  # `from None`: the traceback would carry the statement text

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def connect(target: Target, user: str, password: str, sysdba: bool = False) -> Connection:
    """Thin mode: no Oracle Client install. Raises DBError, never oracledb exceptions."""
    import oracledb
    kw = dict(user=user, password=password, dsn=target.dsn, tcp_connect_timeout=target.timeout,
              retry_count=0, disable_oob=target.disable_oob)
    if sysdba:
        kw["mode"] = oracledb.AUTH_MODE_SYSDBA
    try:
        conn = oracledb.connect(**kw)
        conn.call_timeout = int(target.timeout * 1000)
        return Connection(conn)
    except oracledb.Error as e:
        raise _wrap(e) from None
