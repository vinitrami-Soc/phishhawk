"""Run one function in a child process with memory and CPU limits, so a
hostile message cannot take the worker (or the web app) down with it.
Linux and macOS only: it uses the resource module."""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from typing import Any

MB = 1024 * 1024


class LimitExceeded(Exception):
    """The child hit its memory or CPU limit, or ran past the wall-clock limit."""


class ChildFailed(Exception):
    """The function raised in the child; the message is safe to show."""


def _child(conn: Any, fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (memory_mb * MB, memory_mb * MB))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    try:
        conn.send(("ok", fn(*args)))
    except MemoryError:
        conn.send(("limit", "memory"))
    except BaseException as exc:  # anything the engine raises becomes a failed analysis
        conn.send(("error", "%s: %s" % (type(exc).__name__, str(exc)[:300])))
    finally:
        conn.close()


def run_limited(fn: Callable[..., Any], args: tuple[Any, ...], memory_mb: int, cpu_seconds: int,
                on_wait: Callable[[], None] | None = None) -> Any:
    """fn(*args) in a fresh process; on_wait is called every few seconds while
    waiting (the worker uses it to send its heartbeat)."""
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_child, args=(sender, fn, args, memory_mb, cpu_seconds), daemon=True)
    process.start()
    sender.close()
    waited, wall = 0.0, cpu_seconds * 2 + 10
    try:
        while not receiver.poll(5):
            waited += 5
            if on_wait is not None:
                on_wait()
            if waited >= wall or not process.is_alive() and not receiver.poll(0):
                raise LimitExceeded("time" if waited >= wall else "the analysis process stopped")
        try:
            status, value = receiver.recv()
        except EOFError as exc:  # killed by the CPU limit before it could answer
            raise LimitExceeded("cpu") from exc
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
        receiver.close()
    if status == "limit":
        raise LimitExceeded(value)
    if status == "error":
        raise ChildFailed(value)
    return value
