"""SQLite storage for validated M6 SecurityEvents, independent of collection."""

from contextlib import contextmanager
from dataclasses import fields
import json
import sqlite3

if __package__:
    from .events import SecurityEvent
else:
    from events import SecurityEvent

SCHEMA_VERSION = 1
COLUMNS = tuple(item.name for item in fields(SecurityEvent))
COLUMN_SQL = ", ".join(COLUMNS)

# Timestamp is decimal TEXT to retain the entire sensor uint64 range. All
# other current numeric fields fit SQLite's signed 64-bit INTEGER type.
MIGRATION_1 = """
CREATE TABLE events (
    event_id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL,
    source TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    gid INTEGER,
    process_name TEXT,
    process_path TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    tcp_flags INTEGER,
    interface INTEGER,
    syscall TEXT,
    container_id TEXT,
    cgroup_id INTEGER,
    metadata TEXT NOT NULL
)
"""


def validate_pagination(limit, offset):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")
    if type(offset) is not int or not 0 <= offset <= (1 << 63) - 1:
        raise ValueError("offset must be a non-negative SQLite integer")


class EventStore:
    """File-backed store; each operation owns and closes its SQLite connection.

    Call initialize before use. insert is directly usable as an EventRouter
    subscriber. Duplicate event IDs raise sqlite3.IntegrityError, never replace
    existing telemetry. Database errors propagate to the caller.
    """

    def __init__(self, path):
        self.path = str(path)
        if not self.path or self.path == ":memory:":
            raise ValueError("EventStore requires a persistent SQLite file path")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self):
        """Apply v1 atomically, tolerate repeat startup, reject newer schemas."""
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, SCHEMA_VERSION):
                    raise ValueError(f"unsupported database schema version: {version}")
                if version == 0:
                    connection.execute(MIGRATION_1)
                    connection.execute("CREATE INDEX events_category ON events(event_category)")
                    connection.execute("CREATE INDEX events_type ON events(event_type)")
                    connection.execute("PRAGMA user_version=1")

    def insert(self, event):
        if not isinstance(event, SecurityEvent):
            raise ValueError("storage requires a SecurityEvent")
        record = SecurityEvent.from_dict(event.to_dict()).to_dict()
        record["timestamp"] = str(record["timestamp"])
        record["metadata"] = json.dumps(record["metadata"], allow_nan=False, separators=(",", ":"))
        placeholders = ", ".join("?" for _ in COLUMNS)
        with self._connection() as connection, connection:
            connection.execute(f"INSERT INTO events ({COLUMN_SQL}) VALUES ({placeholders})",
                               tuple(record[column] for column in COLUMNS))

    @staticmethod
    def _decode(row):
        record = dict(row)
        record["timestamp"] = int(record["timestamp"])
        record["metadata"] = json.loads(record["metadata"])
        return SecurityEvent.from_dict(record)

    def get(self, event_id):
        with self._connection() as connection:
            row = connection.execute(
                f"SELECT {COLUMN_SQL} FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return None if row is None else self._decode(row)

    def list_events(self, *, limit=100, offset=0, event_category=None, event_type=None):
        """Return insertion order (oldest first); filters combine with AND."""
        validate_pagination(limit, offset)
        clauses, values = [], []
        for column, value in (("event_category", event_category), ("event_type", event_type)):
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{column} must be a string")
                clauses.append(f"{column} = ?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT {COLUMN_SQL} FROM events{where} ORDER BY rowid LIMIT ? OFFSET ?",
                (*values, limit, offset)).fetchall()
        return [self._decode(row) for row in rows]

    def check_health(self):
        """Check database access, version, and event table availability."""
        with self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise sqlite3.DatabaseError("database schema version mismatch")
            connection.execute(f"SELECT {COLUMN_SQL} FROM events LIMIT 0")
