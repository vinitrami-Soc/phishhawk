"""The analysis child process: results come back, and limits hold."""

import time

import pytest

from phishhawk.server.limits import ChildFailed, LimitExceeded, run_limited


def _double(value):
    return value * 2


def _hog_memory():
    return len(bytearray(1024 * 1024 * 1024))


def _spin():
    while True:
        pass


def _raise():
    raise ValueError("a broken message")


def test_a_result_comes_back_from_the_child():
    assert run_limited(_double, (21,), memory_mb=512, cpu_seconds=10) == 42


def test_the_memory_limit_stops_the_child():
    with pytest.raises(LimitExceeded):
        run_limited(_hog_memory, (), memory_mb=256, cpu_seconds=10)


def test_the_cpu_limit_stops_the_child():
    started = time.monotonic()
    with pytest.raises(LimitExceeded):
        run_limited(_spin, (), memory_mb=512, cpu_seconds=1)
    assert time.monotonic() - started < 15


def test_an_exception_in_the_child_is_reported_not_raised_raw():
    with pytest.raises(ChildFailed, match="ValueError: a broken message"):
        run_limited(_raise, (), memory_mb=512, cpu_seconds=10)
