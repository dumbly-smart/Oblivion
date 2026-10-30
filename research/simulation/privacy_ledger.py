"""Durable, privacy-preserving composition accounting for local experiments.

The ledger persists keyed pseudonyms and exact decimal budgets in SQLite. It
does not provide rollback protection: a privileged operator can restore an old
database backup and thereby erase later accounting state.
"""
from decimal import Decimal
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import sqlite3
import stat


_SCHEMA_VERSION = 1
_KEY_BYTES = 32
_MAX_IDENTIFIERS = 1_000_000


def _number(name, value, *, less_than_one=False):
    if value is None:
        return None
    try:
        finite = math.isfinite(value)
    except (OverflowError, TypeError):
        finite = False
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not finite or value < 0 or less_than_one and value >= 1):
        suffix = " and less than one" if less_than_one else ""
        raise ValueError(f"{name} must be finite and nonnegative{suffix}")
    return Decimal(str(value))


def _private_regular_file(path, *, label, expected_bytes=None):
    if os.name != "posix":
        raise ValueError("persistent privacy ledger requires POSIX file permissions")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"unable to securely open {label}") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError(f"{label} must be an owner-owned regular file with private permissions")
        chunks = []
        size = 0
        while size <= (expected_bytes or 0):
            chunk = os.read(descriptor, (expected_bytes or 0) + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        content = b"".join(chunks)
        if expected_bytes is not None and len(content) != expected_bytes:
            raise ValueError(f"{label} must contain exactly {expected_bytes} bytes")
        return content, metadata
    finally:
        os.close(descriptor)


class PersistentUserPrivacyLedger:
    """SQLite-backed basic sequential composition keyed by stable principals.

    Only domain-separated HMAC tokens for release and principal identifiers
    are persisted. The raw identifiers and HMAC key remain in process memory.
    Each multi-principal release is checked and committed in one serialized
    transaction, so budget rejection cannot partially charge a release.
    """

    def __init__(self, database_path, key_path, max_epsilon=None, max_delta=None,
                 identity_registry_sha256=None):
        self._max_epsilon = _number("max_epsilon", max_epsilon)
        self._max_delta = _number("max_delta", max_delta, less_than_one=True)
        if (identity_registry_sha256 is not None
                and (not isinstance(identity_registry_sha256, str)
                     or not re.fullmatch(r"[0-9a-f]{64}", identity_registry_sha256))):
            raise ValueError("identity registry fingerprint must be lowercase SHA-256")
        self._identity_registry_sha256 = identity_registry_sha256
        self._database = Path(database_path).absolute()
        self._key_path = Path(key_path).absolute()
        if self._database == self._key_path:
            raise ValueError("ledger database and HMAC key must be different files")
        key, key_metadata = _private_regular_file(
            self._key_path, label="ledger key file", expected_bytes=_KEY_BYTES)
        self._key = key
        self._key_inode = (key_metadata.st_dev, key_metadata.st_ino)
        self._key_fingerprint = hashlib.sha256(key).hexdigest()
        self._check_directory()
        self._prepare_database_file()
        self._initialize()

    def _check_directory(self):
        if os.name != "posix":
            raise ValueError("persistent privacy ledger requires POSIX file permissions")
        try:
            metadata = self._database.parent.stat()
        except OSError as error:
            raise ValueError("ledger database directory must already exist") from error
        if (not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError(
                "database directory permissions must be owner-only (0700 or stricter)"
            )

    def _prepare_database_file(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._database, flags, 0o600)
        except FileExistsError:
            _, metadata = _private_regular_file(
                self._database, label="ledger database")
            if (stat.S_IMODE(metadata.st_mode) & 0o077
                    or not stat.S_IMODE(metadata.st_mode) & 0o200):
                raise ValueError("ledger database file must be owner-readable and writable only")
        except OSError as error:
            raise ValueError("unable to securely create ledger database") from error
        else:
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        metadata = self._database.stat(follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) == self._key_inode:
            raise ValueError("ledger database and HMAC key must be distinct files")

    def _connect(self):
        connection = sqlite3.connect(
            str(self._database), timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "ledger_meta" not in tables:
                if tables:
                    raise ValueError("existing database has an unknown schema")
                statements = ("""
                    CREATE TABLE ledger_meta (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        schema_version INTEGER NOT NULL,
                        key_fingerprint TEXT NOT NULL,
                        max_epsilon TEXT,
                        max_delta TEXT,
                        identity_registry_sha256 TEXT
                    )""", """
                    CREATE TABLE releases (
                        release_token TEXT PRIMARY KEY,
                        epsilon TEXT NOT NULL,
                        delta TEXT NOT NULL
                    )""", """
                    CREATE TABLE principals (
                        principal_token TEXT PRIMARY KEY,
                        epsilon TEXT NOT NULL,
                        delta TEXT NOT NULL,
                        release_count INTEGER NOT NULL CHECK (release_count > 0)
                    )""", """
                    CREATE TABLE release_principals (
                        release_token TEXT NOT NULL REFERENCES releases(release_token),
                        principal_token TEXT NOT NULL REFERENCES principals(principal_token),
                        PRIMARY KEY (release_token, principal_token)
                    )""")
                for statement in statements:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version=1")
                connection.execute(
                    "INSERT INTO ledger_meta VALUES (1, ?, ?, ?, ?, ?)",
                    (_SCHEMA_VERSION, self._key_fingerprint,
                     str(self._max_epsilon) if self._max_epsilon is not None else None,
                     str(self._max_delta) if self._max_delta is not None else None,
                     self._identity_registry_sha256))
            else:
                expected_tables = {
                    "ledger_meta", "releases", "principals", "release_principals"}
                if tables != expected_tables:
                    raise ValueError("existing database has an unknown schema")
                if connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
                    raise ValueError("unsupported or malformed privacy ledger schema")
                metadata = connection.execute(
                    "SELECT schema_version, key_fingerprint, max_epsilon, max_delta, "
                    "identity_registry_sha256 "
                    "FROM ledger_meta WHERE singleton=1"
                ).fetchone()
                if metadata is None or metadata[0] != _SCHEMA_VERSION:
                    raise ValueError("unsupported or malformed privacy ledger schema")
                if not hmac.compare_digest(metadata[1], self._key_fingerprint):
                    raise ValueError("privacy ledger key fingerprint mismatch")
                limits = (
                    str(self._max_epsilon) if self._max_epsilon is not None else None,
                    str(self._max_delta) if self._max_delta is not None else None,
                )
                if metadata[2:4] != limits:
                    raise ValueError("privacy ledger budget configuration mismatch")
                if metadata[4] != self._identity_registry_sha256:
                    raise ValueError("privacy ledger identity registry fingerprint mismatch")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        database_mode = stat.S_IMODE(self._database.stat().st_mode)
        if database_mode & 0o077 or not database_mode & 0o200:
            raise ValueError("ledger database file must be owner-readable and writable only")

    @staticmethod
    def _validate_record(release_id, user_ids, epsilon, delta):
        if not isinstance(release_id, str) or not release_id or len(release_id) > 256:
            raise ValueError("release_id must be a nonempty string of at most 256 characters")
        try:
            if len(release_id.encode("utf-8")) > 1024:
                raise ValueError("release_id UTF-8 encoding exceeds 1024 bytes")
        except UnicodeEncodeError as error:
            raise ValueError("release_id must be valid UTF-8 text") from error
        epsilon_value = _number("release epsilon", epsilon)
        delta_value = _number("release delta", delta, less_than_one=True)
        if isinstance(user_ids, (str, bytes)):
            raise ValueError("release principal IDs must be a collection, not a string")
        try:
            principals = []
            for user_id in user_ids:
                if len(principals) >= _MAX_IDENTIFIERS:
                    raise ValueError("release contains too many principal IDs")
                principals.append(user_id)
        except TypeError as error:
            raise ValueError("release principal IDs must be iterable") from error
        for user_id in principals:
            if not isinstance(user_id, str) or not user_id:
                raise ValueError("release principal IDs must be unique nonempty bounded strings")
            try:
                if len(user_id.encode("utf-8")) > 4096:
                    raise ValueError("release principal ID exceeds 4096 UTF-8 bytes")
            except UnicodeEncodeError as error:
                raise ValueError("release principal IDs must be valid UTF-8 text") from error
        if len(set(principals)) != len(principals):
            raise ValueError("release principal IDs must be unique nonempty bounded strings")
        return principals, epsilon_value, delta_value

    def _token(self, domain, value):
        encoded = value.encode("utf-8")
        message = b"oblivion-user-privacy-ledger-v1\x00" + domain + b"\x00" + encoded
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def record(self, release_id, user_ids, epsilon, delta):
        principals, epsilon_value, delta_value = self._validate_record(
            release_id, user_ids, epsilon, delta)
        release_token = self._token(b"release", release_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._check_key(connection)
            if connection.execute(
                    "SELECT 1 FROM releases WHERE release_token=?",
                    (release_token,)).fetchone():
                raise ValueError("duplicate privacy release ID")
            for user_id in principals:
                principal_token = self._token(b"principal", user_id)
                previous = connection.execute(
                    "SELECT epsilon, delta, release_count FROM principals WHERE principal_token=?",
                    (principal_token,)).fetchone()
                old_epsilon, old_delta, old_count = (
                    (Decimal(previous[0]), Decimal(previous[1]), previous[2])
                    if previous else (Decimal(0), Decimal(0), 0))
                new_epsilon = old_epsilon + epsilon_value
                new_delta = old_delta + delta_value
                if (self._max_epsilon is not None and new_epsilon > self._max_epsilon
                        or self._max_delta is not None and new_delta > self._max_delta):
                    raise ValueError("privacy budget exceeded")
            connection.execute(
                "INSERT INTO releases VALUES (?, ?, ?)",
                (release_token, str(epsilon_value), str(delta_value)))
            for user_id in principals:
                principal_token = self._token(b"principal", user_id)
                previous = connection.execute(
                    "SELECT epsilon, delta, release_count FROM principals WHERE principal_token=?",
                    (principal_token,)).fetchone()
                old_epsilon, old_delta, old_count = (
                    (Decimal(previous[0]), Decimal(previous[1]), previous[2])
                    if previous else (Decimal(0), Decimal(0), 0))
                new_epsilon = old_epsilon + epsilon_value
                new_delta = old_delta + delta_value
                connection.execute("""
                    INSERT INTO principals VALUES (?, ?, ?, ?)
                    ON CONFLICT(principal_token) DO UPDATE SET
                        epsilon=excluded.epsilon,
                        delta=excluded.delta,
                        release_count=excluded.release_count
                """, (principal_token, str(new_epsilon), str(new_delta), old_count + 1))
                connection.execute(
                    "INSERT INTO release_principals VALUES (?, ?)",
                    (release_token, principal_token))
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _check_key(self, connection):
        metadata = connection.execute(
            "SELECT schema_version, key_fingerprint, max_epsilon, max_delta, "
            "identity_registry_sha256 "
            "FROM ledger_meta WHERE singleton=1"
        ).fetchone()
        if metadata is None or metadata[0] != _SCHEMA_VERSION:
            raise ValueError("unsupported or malformed privacy ledger schema")
        if not hmac.compare_digest(metadata[1], self._key_fingerprint):
            raise ValueError("privacy ledger key fingerprint mismatch")
        limits = (
            str(self._max_epsilon) if self._max_epsilon is not None else None,
            str(self._max_delta) if self._max_delta is not None else None,
        )
        if metadata[2:4] != limits:
            raise ValueError("privacy ledger budget configuration mismatch")
        if metadata[4] != self._identity_registry_sha256:
            raise ValueError("privacy ledger identity registry fingerprint mismatch")

    def summary(self):
        connection = self._connect()
        try:
            self._check_key(connection)
            release_count = connection.execute(
                "SELECT COUNT(*) FROM releases").fetchone()[0]
            values = connection.execute(
                "SELECT epsilon, delta, release_count FROM principals")
            max_epsilon = Decimal(0)
            max_delta = Decimal(0)
            max_releases = 0
            for epsilon, delta, count in values:
                max_epsilon = max(max_epsilon, Decimal(epsilon))
                max_delta = max(max_delta, Decimal(delta))
                max_releases = max(max_releases, count)
        finally:
            connection.close()
        return dict(
            ledger_schema_version=_SCHEMA_VERSION,
            ledger_key_fingerprint=self._key_fingerprint,
            identity_registry_sha256=self._identity_registry_sha256,
            max_epsilon_budget=(float(self._max_epsilon)
                                if self._max_epsilon is not None else None),
            max_delta_budget=(float(self._max_delta)
                              if self._max_delta is not None else None),
            release_count=release_count,
            max_user_release_count=max_releases,
            max_user_epsilon=float(max_epsilon),
            max_user_delta=float(max_delta),
            principal_identifiers_emitted=False,
            principal_identifiers_stored_as="domain-separated HMAC-SHA256 pseudonyms",
        )
