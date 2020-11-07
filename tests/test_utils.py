import pytest

from poshc2.Utils import validate_sleep_time


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