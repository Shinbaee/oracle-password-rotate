"""Decision logic and statement building, against tests/fake_db.py. No database needed."""

import pytest
from fake_db import FakeDB

from oracle_password_rotate import cli, flow
from oracle_password_rotate.names import BadValue, alter_user_sql, candidates

NEW = "Rotated-pass-2026"
OLD = "Initial-pass-001"
ADMIN = "Admin-pass-0001"


@pytest.fixture
def db():
    return FakeDB()


def run(db, monkeypatch, *extra, account="APP_SVC", new=NEW, old=OLD, admin=True):
    monkeypatch.setenv("T_NEW", new)
    argv = ["--host", "db.example.test", "--service", "APPPDB", "--account", account, "--new-password-env", "T_NEW"]
    if old is not None:
        monkeypatch.setenv("T_OLD", old)
        argv += ["--old-password-env", "T_OLD"]
    if admin:
        monkeypatch.setenv("T_ADMIN", ADMIN)
        argv += ["--admin-user", "SYSTEM", "--admin-password-env", "T_ADMIN"]
    return cli.main(argv + list(extra), connect_fn=db.connect)


def output(capsys, *secrets):
    out = capsys.readouterr()
    for s in secrets:
        assert s not in out.out + out.err
    return out


# --- statement building ---

def test_alter_user_quotes_the_name_and_both_passwords():
    assert alter_user_sql("APP_SVC", "N3w-pass") == 'ALTER USER "APP_SVC" IDENTIFIED BY "N3w-pass"'
    assert alter_user_sql("Mixed", "a", "b") == 'ALTER USER "Mixed" IDENTIFIED BY "a" REPLACE "b"'


@pytest.mark.parametrize("pw", ['ab"; DROP USER x', "line\nbreak", "", "x" * 1025])
def test_password_that_could_break_the_statement_is_refused(pw):
    with pytest.raises(BadValue):
        alter_user_sql("APP_SVC", pw)


def test_candidates():
    assert candidates("app_svc") == ["APP_SVC", "app_svc"]
    assert candidates("APP_SVC") == ["APP_SVC"]
    assert candidates("Has Space") == ["Has Space"]
    with pytest.raises(BadValue):
        candidates('x" IDENTIFIED BY "y')


# --- admin mode ---

def test_admin_change_and_verify(db, monkeypatch, capsys):
    assert run(db, monkeypatch) == flow.OK
    assert db.users["APP_SVC"].password == NEW
    assert db.statements == [f'ALTER USER "APP_SVC" IDENTIFIED BY "{NEW}"']
    assert db.attempts[-1] == ("APP_SVC", True)
    out = output(capsys, NEW, OLD, ADMIN)
    assert out.out.strip() == "OK: password of APP_SVC changed and verified"


def test_lower_case_name_is_found(db, monkeypatch, capsys):
    assert run(db, monkeypatch, account="app_svc") == flow.OK
    assert "stored as 'APP_SVC'" in capsys.readouterr().err


def test_ambiguous_name_is_not_guessed(db, monkeypatch, capsys):
    db.users["app_svc"] = db.users["APP_SVC"].__class__("Other-pass-00001")
    assert run(db, monkeypatch, account="app_svc") == flow.NOT_FOUND
    assert db.statements == []  # nothing was changed
    assert "matches 2 accounts" in capsys.readouterr().out


def test_injection_through_the_account_name_changes_nothing(db, monkeypatch, capsys):
    assert run(db, monkeypatch, account="APP_SVC ACCOUNT UNLOCK") == flow.NOT_FOUND
    assert db.statements == []


def test_missing_account(db, monkeypatch, capsys):
    assert run(db, monkeypatch, account="NOBODY") == flow.NOT_FOUND


def test_wrong_admin_password(db, monkeypatch, capsys):
    db.users["SYSTEM"].password = "something-else"
    assert run(db, monkeypatch) == flow.SIGN_IN_FAILED
    assert db.statements == []


def test_unreachable(db, monkeypatch, capsys):
    db.down = True
    assert run(db, monkeypatch) == flow.UNREACHABLE


def test_policy_and_reuse_are_rejections(db, monkeypatch, capsys):
    assert run(db, monkeypatch, new="Short-1") == flow.REJECTED
    assert "ORA-28003" in output(capsys, "Short-1").out
    db.users["APP_SVC"].history.append("Used-before-2025")
    assert run(db, monkeypatch, new="Used-before-2025") == flow.REJECTED
    assert "ORA-28007" in capsys.readouterr().out
    assert db.users["APP_SVC"].password == OLD


def test_double_quote_in_password_is_refused_before_connecting(db, monkeypatch, capsys):
    assert run(db, monkeypatch, new='Has"Quote-pass1') == flow.REJECTED
    assert db.attempts == []


def test_locked_account_takes_the_password_but_cannot_sign_in(db, monkeypatch, capsys):
    """The case behind "change succeeded, account keeps getting locked": ALTER USER works on a locked account."""
    db.users["APP_SVC"].locked = True
    assert run(db, monkeypatch) == flow.CANNOT_SIGN_IN
    assert db.users["APP_SVC"].password == NEW
    assert "account is locked (ORA-28000)" in capsys.readouterr().out


def test_no_create_session(db, monkeypatch, capsys):
    db.users["APP_SVC"].create_session = False
    assert run(db, monkeypatch) == flow.CANNOT_SIGN_IN


def test_statement_ran_but_nothing_changed(db, monkeypatch, capsys):
    db.silent_no_save = True
    assert run(db, monkeypatch) == flow.NOT_CHANGED


def test_no_diagnose_spends_one_failed_attempt_only(db, monkeypatch, capsys):
    db.silent_no_save = True
    assert run(db, monkeypatch, "--no-diagnose") == flow.UNVERIFIED
    assert [a for a in db.attempts if a[0] == "APP_SVC"] == [("APP_SVC", False)]
    assert db.users["APP_SVC"].failures == 1


def test_both_refused(db, monkeypatch, capsys):
    db.store_other = True
    assert run(db, monkeypatch) == flow.BOTH_REFUSED


# --- self mode ---

def test_self_mode_uses_replace(db, monkeypatch, capsys):
    assert run(db, monkeypatch, admin=False) == flow.OK
    assert db.statements == [f'ALTER USER "APP_SVC" IDENTIFIED BY "{NEW}" REPLACE "{OLD}"']
    assert db.users["APP_SVC"].password == NEW


def test_self_mode_with_wrong_old_password(db, monkeypatch, capsys):
    assert run(db, monkeypatch, admin=False, old="Wrong-old-pass1") == flow.SIGN_IN_FAILED


# --- usage ---

def test_self_mode_needs_the_old_password(db, monkeypatch, capsys):
    assert run(db, monkeypatch, admin=False, old=None) == flow.USAGE


def test_new_equal_to_old(db, monkeypatch, capsys):
    assert run(db, monkeypatch, new=OLD) == flow.USAGE
    assert db.attempts == []
