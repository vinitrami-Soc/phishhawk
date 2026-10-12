"""A small IMAP server over TLS for the mailbox tests (spec 7.5). It serves folders of messages, records every
command, and answers only reads: CAPABILITY, LOGIN, STARTTLS, EXAMINE, UID SEARCH, UID FETCH of RFC822.SIZE or
BODY.PEEK[], NOOP and LOGOUT. Anything else (SELECT, STORE, COPY, MOVE, EXPUNGE, a FETCH that would set \\Seen)
is recorded as a violation and refused. Its certificate is signed by a CA made for the test; point
SSL_CERT_FILE at `ca_file` so the client verifies it as it would a real server's."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ATOM = re.compile(rb'"((?:[^"\\]|\\.)*)"|(\S+)')


def _certificates(folder: Path) -> tuple[Path, Path, Path]:
    """A CA, and a certificate for 127.0.0.1 and localhost that it signed."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PhishHawk test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    server = (x509.CertificateBuilder()
              .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
              .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                          x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                             critical=False)
              .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                             critical=False)
              .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    ca_file, cert_file, key_file = folder / "ca.pem", folder / "server.pem", folder / "server.key"
    ca_file.write_bytes(ca.public_bytes(pem))
    cert_file.write_bytes(server.public_bytes(pem))
    key_file.write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_file, cert_file, key_file


class FakeImapServer:
    def __init__(self, folder: Path, user: str, password: str, starttls: bool = False) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        self.ca_file, cert_file, key_file = _certificates(folder)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        self.user, self.password, self.starttls = user, password, starttls
        self.folders: dict[str, list[tuple[int, bytes]]] = {"INBOX": []}
        self.uidvalidity, self.next_uid = 1, 1
        self.commands: list[str] = []  # every command as received, the password masked
        self.violations: list[str] = []
        self.drop_after_fetches: int | None = None  # hang up after this many message fetches
        self.fetches = 0
        self._lock = threading.Lock()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def add(self, raw: bytes, folder: str = "INBOX") -> int:
        with self._lock:
            uid, self.next_uid = self.next_uid, self.next_uid + 1
            self.folders.setdefault(folder, []).append((uid, raw))
            return uid

    def renumber(self) -> None:
        """A new UIDVALIDITY, and every message a new UID (as after the server rebuilt the folder)."""
        with self._lock:
            self.uidvalidity += 1
            for name, messages in self.folders.items():
                renumbered = []
                for _, raw in messages:
                    renumbered.append((self.next_uid, raw))
                    self.next_uid += 1
                self.folders[name] = renumbered

    def close(self) -> None:
        self._listener.close()

    # ------------------------------------------------------------------ protocol --

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(client,), daemon=True).start()

    def _session(self, raw_socket: socket.socket) -> None:
        connection: socket.socket = raw_socket
        try:
            if not self.starttls:
                connection = self.context.wrap_socket(raw_socket, server_side=True)
            self._talk(connection)
        except (OSError, ssl.SSLError):
            pass
        finally:
            connection.close()

    def _talk(self, connection: socket.socket) -> None:
        reader = connection.makefile("rb")
        send = connection.sendall
        send(b"* OK PhishHawk test IMAP server ready\r\n")
        state = {"user": False, "folder": None}
        while True:
            line = reader.readline()
            if not line:
                return
            tag, _, rest = line.rstrip(b"\r\n").partition(b" ")
            command, _, args = rest.partition(b" ")
            name = command.upper().decode("ascii", "replace")
            if name == "UID":
                sub, _, args = args.partition(b" ")
                name = "UID " + sub.upper().decode("ascii", "replace")
            shown = "LOGIN ***" if name == "LOGIN" else (name + " " + args.decode("utf-8", "replace")).strip()
            self.commands.append(shown)
            reply = self._answer(name, args, state, send, connection)
            if reply == "starttls":
                send(tag + b" OK Begin TLS negotiation now\r\n")
                connection = self.context.wrap_socket(connection, server_side=True)
                reader, send = connection.makefile("rb"), connection.sendall
                continue
            if reply is None:  # hung up
                connection.close()
                return
            send(tag + b" " + reply + b"\r\n")
            if name == "LOGOUT":
                return

    def _refuse(self, what: str) -> bytes:
        self.violations.append(what)
        return b"BAD only reads are allowed here"

    def _answer(self, name: str, args: bytes, state: dict, send, connection) -> bytes | str | None:  # noqa: ANN001
        if name == "CAPABILITY":
            send(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN%s\r\n" % (b" STARTTLS" if self.starttls else b""))
            return b"OK CAPABILITY completed"
        if name in ("NOOP", "LOGOUT"):
            if name == "LOGOUT":
                send(b"* BYE logging out\r\n")
            return b"OK done"
        if name == "STARTTLS":
            return "starttls" if self.starttls else b"BAD already secure"
        if name == "LOGIN":
            words = [m.group(1) if m.group(1) is not None else m.group(2) for m in ATOM.finditer(args)]
            words = [re.sub(rb"\\(.)", rb"\1", w) for w in words]
            if len(words) == 2 and words[0].decode() == self.user and words[1].decode() == self.password:
                state["user"] = True
                return b"OK LOGIN completed"
            return b"NO [AUTHENTICATIONFAILED] Invalid credentials"
        if not state["user"]:
            return b"NO sign in first"
        if name == "EXAMINE":
            folder = ATOM.match(args)
            wanted = (folder.group(1) if folder and folder.group(1) is not None else args).decode("utf-8")
            if wanted not in self.folders:
                return b"NO no such folder"
            state["folder"] = wanted
            with self._lock:
                count, uidnext = len(self.folders[wanted]), self.next_uid
            send(b"* %d EXISTS\r\n* 0 RECENT\r\n" % count)
            send(b"* OK [UIDVALIDITY %d] UIDs valid\r\n* OK [UIDNEXT %d] next\r\n" % (self.uidvalidity, uidnext))
            return b"OK [READ-ONLY] EXAMINE completed"
        if name == "UID SEARCH" and state["folder"]:
            with self._lock:
                uids = [uid for uid, _ in self.folders[state["folder"]]]
            found = re.search(rb"UID (\d+):\*", args)
            if found and uids:
                low = int(found.group(1))
                top = max(uids)
                # n:* covers top..n when n is past the last UID: the newest message is always in it
                low, high = (low, top) if low <= top else (top, low)
                uids = [uid for uid in uids if low <= uid <= high]
            send(b"* SEARCH%s\r\n" % b"".join(b" %d" % uid for uid in uids))
            return b"OK SEARCH completed"
        if name == "UID FETCH" and state["folder"]:
            uid_text, _, items = args.partition(b" ")
            with self._lock:
                messages = self.folders[state["folder"]]
                found = [(seq, raw) for seq, (uid, raw) in enumerate(messages, 1) if uid == int(uid_text)]
            if items == b"(RFC822.SIZE)":
                for seq, raw in found:
                    send(b"* %d FETCH (UID %s RFC822.SIZE %d)\r\n" % (seq, uid_text, len(raw)))
                return b"OK FETCH completed"
            if items == b"(BODY.PEEK[])":
                if self.drop_after_fetches is not None and self.fetches >= self.drop_after_fetches:
                    return None
                self.fetches += 1
                for seq, raw in found:
                    send(b"* %d FETCH (UID %s BODY[] {%d}\r\n" % (seq, uid_text, len(raw)) + raw + b")\r\n")
                return b"OK FETCH completed"
            return self._refuse("UID FETCH " + items.decode("ascii", "replace"))
        return self._refuse(name)
