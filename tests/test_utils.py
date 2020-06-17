import pytest

from poshc2.Utils import validate_sleep_time, validate_killdate


def test_validate_sleep_time():
    assert validate_sleep_time("5h") is not None
    assert validate_sleep_time("4m") is not None
    assert validate_sleep_time("3s ") is not None
    assert validate_sleep_time(" 5000h ") is not None
    assert validate_sleep_time(" 999 s  ") is None
    assert validate_sleep_time("999 s") is None
    assert validate_sleep_time("999d") is None
    assert validate_sleep_time("s") is None
    assert validate_sleep_time("asdf") is None
    assert validate_sleep_time("") is None
    assert validate_sleep_time(None) is None


def test_validate_killdate():
    assert not validate_killdate("0123-45-67")
    assert not validate_killdate("0000-00-0")
    assert not validate_killdate("bad")
    assert not validate_killdate("")
    assert not validate_killdate("2020-01-45")
    assert not validate_killdate("2020-13-01")
    assert validate_killdate("2020-01-01")
    assert validate_killdate(" 2020-01-01 ")