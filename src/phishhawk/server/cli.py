"""phishhawk server: run the web app and its worker, and the admin tasks that
need no web page (migrate, create-admin, rotate-key, audit verify)."""

from __future__ import annotations

import argparse
import getpass
import multiprocessing
import os
import signal
import sys
from types import FrameType

from pydantic import ValidationError

from . import audit, auth, rotation
from .app import build_services
from .config import ServerSettings, load_settings
from .crypto import Box, DecryptError
from .db import migrate, transaction

EXIT_FAILED, EXIT_ERROR = 1, 3


class CliError(Exception):
    """A problem to report in one line, with exit code 3."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishhawk server",
        description="Run the PhishHawk web app. Settings come from PHISHHAWK_* environment variables; "
                    "see docs/SERVER.md.")
    actions = parser.add_subparsers(dest="action", metavar="<action>", required=True)
    actions.add_parser("run", help="bring the database up to date, then start the web app and one worker")
    actions.add_parser("worker", help="run a worker without the web app")
    actions.add_parser("migrate", help="create the database or bring it up to date")
    admin = actions.add_parser("create-admin", help="create an admin user (the first one, or another)")
    admin.add_argument("username")
    admin.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    actions.add_parser("rotate-key", help="re-encrypt everything under PHISHHAWK_NEW_ENCRYPTION_KEY "
                                          "(stop the server first)")
    log = actions.add_parser("audit", help="audit log tasks")
    log.add_subparsers(dest="audit_action", metavar="<task>", required=True).add_parser(
        "verify", help="check the audit log's hash chain")
    return parser


def settings_or_error() -> ServerSettings:
    """The settings, or a CliError naming each bad variable but never its value."""
    try:
        settings = load_settings()
        Box.from_b64(settings.encryption_key.get_secret_value())
        return settings
    except ValidationError as exc:
        names = sorted({"PHISHHAWK_" + str(error["loc"][0]).upper() for error in exc.errors()})
        raise CliError("missing or not valid: " + ", ".join(names)) from None
    except ValueError as exc:
        raise CliError(str(exc)) from None


def _password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Password again: "):
        raise CliError("the passwords do not match")
    return first


def _plural(count: int, word: str) -> str:
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def create_admin(settings: ServerSettings, username: str, from_stdin: bool) -> int:
    password = _password(from_stdin)
    with transaction(build_services(settings).sessions) as db:
        try:
            user = auth.create_user(db, username, password, "admin")
        except auth.AuthError as exc:
            raise CliError(str(exc)) from None
        audit.record(db, "cli", "user_create", "user", user.id, {"username": user.username, "role": "admin"},
                     workspace_id=user.workspace_id)
    print("created admin %s" % username)
    return 0


def rotate_key(settings: ServerSettings) -> int:
    text = os.environ.get("PHISHHAWK_NEW_ENCRYPTION_KEY", "")
    if not text:
        raise CliError("set PHISHHAWK_NEW_ENCRYPTION_KEY to the new key (32 bytes, base64)")
    try:
        new_box = Box.from_b64(text)
    except ValueError:
        raise CliError("PHISHHAWK_NEW_ENCRYPTION_KEY must be 32 bytes in base64") from None
    services = build_services(settings)
    try:
        with transaction(services.sessions) as db:
            counts = rotation.rotate(db, services.store, new_box, actor="cli")
    except DecryptError:
        raise CliError("a stored value opens under neither key; nothing was deleted, and the rotation can be "
                       "run again once PHISHHAWK_ENCRYPTION_KEY is the current key") from None
    print("re-encrypted %s and %s. Now set PHISHHAWK_ENCRYPTION_KEY to the new key and start the server."
          % (_plural(counts["blobs"], "blob"), _plural(counts["secrets"], "secret")))
    return 0


def verify_audit(settings: ServerSettings) -> int:
    from sqlalchemy import func, select

    from .models import AuditRecord

    with transaction(build_services(settings).sessions) as db:
        problems = audit.verify(db)
        count = db.scalar(select(func.count()).select_from(AuditRecord)) or 0
    if problems:
        print("\n".join(problems))
        return EXIT_FAILED
    print("audit log verified: %s" % _plural(count, "record"))
    return 0


def run_worker(parent: int | None = None) -> None:
    """The worker loop until SIGTERM or SIGINT, or until the server process
    that started it is gone; the job in hand is finished first."""
    from .worker import run_forever

    stop = []

    def _stop(signum: int, frame: FrameType | None) -> None:
        stop.append(signum)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    orphaned = (lambda: os.getppid() != parent) if parent else (lambda: False)
    run_forever(build_services(settings_or_error()), should_stop=lambda: bool(stop) or orphaned())


def _exit_cleanly(signum: int, frame: FrameType | None) -> None:
    raise SystemExit(0)


def serve(settings: ServerSettings) -> int:
    import uvicorn

    migrate(settings.db_url)
    # uvicorn raises the signal again once it has shut down; this turns it into
    # an exception, so the finally block below stops the worker
    signal.signal(signal.SIGTERM, _exit_cleanly)
    signal.signal(signal.SIGINT, _exit_cleanly)
    worker = multiprocessing.get_context("spawn").Process(target=run_worker, args=(os.getpid(),),
                                                          name="phishhawk-worker")
    worker.start()
    try:
        uvicorn.run("phishhawk.server.app:create_app", factory=True, host=settings.host, port=settings.port,
                    ssl_certfile=settings.tls_cert or None, ssl_keyfile=settings.tls_key or None,
                    server_header=False, proxy_headers=False)  # the app reads them (PHISHHAWK_TRUSTED_PROXIES)
    finally:
        worker.terminate()
        worker.join(30)
        if worker.is_alive():
            worker.kill()
    return 0


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = settings_or_error()
        if args.action == "migrate":
            migrate(settings.db_url)
            print("database is up to date")
            return 0
        if args.action == "create-admin":
            return create_admin(settings, args.username, args.password_stdin)
        if args.action == "rotate-key":
            return rotate_key(settings)
        if args.action == "audit":
            return verify_audit(settings)
        if args.action == "worker":
            run_worker()
            return 0
        return serve(settings)
    except CliError as exc:
        print("phishhawk server: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
