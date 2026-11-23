"""Against a real Oracle database (CI: Oracle XE 21c in a container). Skipped unless ORACLE_SYS_PASSWORD is set.

    ORACLE_SYS_PASSWORD   password of SYS and SYSTEM
    ORACLE_TEST_HOST/PORT/SERVICE   default localhost / 1521 / XEPDB1
    SSH_TEST_KEY          private key for ssh $USER@localhost; enables the tunnel tests
"""

import getpass
import os

import oracledb
import pytest

from oracle_password_rotate import cli, flow

SYS_PW = os.environ.get("ORACLE_SYS_PASSWORD")
HOST = os.environ.get("ORACLE_TEST_HOST", "localhost")
PORT = int(os.environ.get("ORACLE_TEST_PORT", "1521"))
SERVICE = os.environ.get("ORACLE_TEST_SERVICE", "XEPDB1")
SSH_KEY = os.environ.get("SSH_TEST_KEY")

pytestmark = pytest.mark.skipif(not SYS_PW, reason="no test database (set ORACLE_SYS_PASSWORD)")

INITIAL = "Initial-pass-0001"
NEW = "Rotated-pass-2026"
DSN = f"{HOST}:{PORT}/{SERVICE}"

VERIFY_FN = """
CREATE OR REPLACE FUNCTION rotate_test_verify(username VARCHAR2, password VARCHAR2, old_password VARCHAR2)
RETURN BOOLEAN IS
BEGIN
  IF LENGTH(password) < 12 THEN
    raise_application_error(-20001, 'Password must be at least 12 characters');
  END IF;
  RETURN TRUE;
END;"""


def sys_conn():
    return oracledb.connect(user="sys", password=SYS_PW, dsn=DSN, mode=oracledb.AUTH_MODE_SYSDBA)


def ignore(cur, sql, *codes):
    try:
        cur.execute(sql)
    except oracledb.DatabaseError as e:
        if e.args[0].full_code not in codes:
            raise


@pytest.fixture(scope="module", autouse=True)
def profile():
    with sys_conn() as c, c.cursor() as cur:
        cur.execute(VERIFY_FN)
        ignore(cur, "DROP PROFILE rotate_test CASCADE", "ORA-02380")
        # wrong password 3 times -> locked; a password can never be reused; at least 12 characters
        cur.execute("CREATE PROFILE rotate_test LIMIT FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME UNLIMITED "
                    "PASSWORD_REUSE_MAX 3 PASSWORD_REUSE_TIME UNLIMITED PASSWORD_VERIFY_FUNCTION rotate_test_verify")


@pytest.fixture
def user(request):
    """A fresh ROT_APP account on the test profile. Mark a test with @pytest.mark.user(locked=..., session=...)."""
    opts = request.node.get_closest_marker("user")
    opts = opts.kwargs if opts else {}
    with sys_conn() as c, c.cursor() as cur:
        ignore(cur, "DROP USER rot_app CASCADE", "ORA-01918")
        cur.execute(f'CREATE USER rot_app IDENTIFIED BY "{INITIAL}" PROFILE rotate_test'
                    + (" ACCOUNT LOCK" if opts.get("locked") else ""))
        if opts.get("session", True):
            cur.execute("GRANT CREATE SESSION TO rot_app")
    return "ROT_APP"


def status():
    with sys_conn() as c, c.cursor() as cur:
        cur.execute("select account_status from dba_users where username = 'ROT_APP'")
        return cur.fetchone()[0]


def can_sign_in(password):
    try:
        oracledb.connect(user="rot_app", password=password, dsn=DSN).close()
        return True
    except oracledb.DatabaseError:
        return False


def run(monkeypatch, *extra, new=NEW, old=INITIAL, admin="SYSTEM", account="ROT_APP"):
    monkeypatch.setenv("T_NEW", new)
    monkeypatch.setenv("T_OLD", old)
    monkeypatch.setenv("T_ADMIN", SYS_PW)
    argv = ["--host", HOST, "--port", str(PORT), "--service", SERVICE, "--account", account,
            "--new-password-env", "T_NEW", "--old-password-env", "T_OLD"]
    if admin:
        argv += ["--admin-user", admin, "--admin-password-env", "T_ADMIN"]
    return cli.main(argv + list(extra))


def clean(capsys):
    out = capsys.readouterr()
    for s in (NEW, INITIAL, SYS_PW):
        assert s not in out.out + out.err
    return out


def test_admin_change(user, monkeypatch, capsys):
    assert run(monkeypatch) == flow.OK
    assert can_sign_in(NEW) and not can_sign_in(INITIAL)
    clean(capsys)


def test_sysdba_and_lower_case_name(user, monkeypatch, capsys):
    assert run(monkeypatch, "--sysdba", admin="sys", account="rot_app") == flow.OK
    assert can_sign_in(NEW)


def test_self_mode_replace(user, monkeypatch, capsys):
    assert run(monkeypatch, admin=None) == flow.OK
    assert can_sign_in(NEW)


def test_verify_function_rejects(user, monkeypatch, capsys):
    assert run(monkeypatch, new="Short-1") == flow.REJECTED
    assert "ORA-28003" in clean(capsys).out
    assert can_sign_in(INITIAL)


def test_reuse_is_rejected(user, monkeypatch, capsys):
    assert run(monkeypatch) == flow.OK
    assert run(monkeypatch, new=INITIAL, old=NEW) == flow.REJECTED
    assert "ORA-28007" in capsys.readouterr().out


@pytest.mark.user(locked=True)
def test_locked_account_is_changed_but_cannot_sign_in(user, monkeypatch, capsys):
    assert run(monkeypatch) == flow.CANNOT_SIGN_IN
    assert "ORA-28000" in capsys.readouterr().out
    assert status() == "LOCKED"  # the tool never unlocks


@pytest.mark.user(locked=True)
def test_locked_account_answers_differently_for_a_wrong_password(user):
    """Recorded, not assumed: does ORA-28000 only come with the right password? If so, receiving it
    after a change also proves the new password is in place."""
    codes = {}
    for label, pw in (("right", INITIAL), ("wrong", "Wrong-pass-00001")):
        try:
            oracledb.connect(user="rot_app", password=pw, dsn=DSN).close()
            codes[label] = "signed in"
        except oracledb.DatabaseError as e:
            codes[label] = e.args[0].full_code
    print("locked account answers:", codes)
    assert codes == {"right": "ORA-28000", "wrong": "ORA-01017"}


@pytest.mark.user(session=False)
def test_no_create_session(user, monkeypatch, capsys):
    assert run(monkeypatch) == flow.CANNOT_SIGN_IN
    assert "ORA-01045" in capsys.readouterr().out


def test_missing_account(user, monkeypatch, capsys):
    assert run(monkeypatch, account="ROT_NOBODY") == flow.NOT_FOUND


def test_wrong_service_is_unreachable(user, monkeypatch, capsys):
    monkeypatch.setenv("T_NEW", NEW)
    monkeypatch.setenv("T_ADMIN", SYS_PW)
    assert cli.main(["--host", HOST, "--port", str(PORT), "--service", "NO_SUCH_SERVICE", "--account", "ROT_APP",
                     "--new-password-env", "T_NEW", "--admin-user", "SYSTEM", "--admin-password-env", "T_ADMIN"]) \
        == flow.UNREACHABLE


def test_self_mode_wrong_old_password_counts_toward_the_lock(user, monkeypatch, capsys):
    for _ in range(3):
        assert run(monkeypatch, admin=None, old="Wrong-old-pass-01") == flow.SIGN_IN_FAILED
    assert status().startswith("LOCKED")


@pytest.mark.skipif(not SSH_KEY, reason="no SSH test key (set SSH_TEST_KEY)")
@pytest.mark.parametrize("oob", [False, True], ids=["oob-default", "oob-disabled"])
def test_through_ssh_tunnel(user, monkeypatch, capsys, oob):
    """Listener reached as 127.0.0.1 from the SSH server's side; only port 22 is used from here."""
    extra = ["--ssh-tunnel", f"{getpass.getuser()}@localhost", "--ssh-key", SSH_KEY] + (["--disable-oob"] if oob else [])
    monkeypatch.setenv("T_NEW", NEW)
    monkeypatch.setenv("T_OLD", INITIAL)
    monkeypatch.setenv("T_ADMIN", SYS_PW)
    code = cli.main(["--host", "127.0.0.1", "--port", str(PORT), "--service", SERVICE, "--account", "ROT_APP",
                     "--new-password-env", "T_NEW", "--old-password-env", "T_OLD",
                     "--admin-user", "SYSTEM", "--admin-password-env", "T_ADMIN"] + extra)
    out = clean(capsys)
    print(out.out, out.err)  # visible with -s / in the CI log on failure
    assert code == flow.OK, out.out
