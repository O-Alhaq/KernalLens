"""Persistence-only UTC clocks. Never used by the security models or engines."""


def migrate_operator_time(connection):
    # No backfill: a pre-existing monotonic value cannot establish calendar time.
    connection.execute("""CREATE TABLE operator_times (
        family TEXT NOT NULL, object_id TEXT NOT NULL,
        created_at TEXT, updated_at TEXT,
        PRIMARY KEY (family, object_id))""")
    now = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
    for family, table in (("event", "events"), ("alert", "alerts"), ("incident", "incidents")):
        connection.execute(f"""CREATE TRIGGER operator_{family}_insert AFTER INSERT ON {table}
            BEGIN INSERT INTO operator_times VALUES
            ('{family}', NEW.{family}_id, {now}, {now}); END""")
    # A legacy Incident's creation time stays unknown even after a new update.
    connection.execute(f"""CREATE TRIGGER operator_incident_update AFTER UPDATE ON incidents
        WHEN OLD.record != NEW.record
        BEGIN INSERT INTO operator_times VALUES ('incident', NEW.incident_id, NULL, {now})
        ON CONFLICT(family, object_id) DO UPDATE SET updated_at=excluded.updated_at; END""")


def project(connection, family, record):
    """Attach presentation fields without modifying the serialized security record."""
    row = connection.execute(
        "SELECT created_at, updated_at FROM operator_times WHERE family=? AND object_id=?",
        (family, record[f"{family}_id"])).fetchone()
    if family == "incident":
        return dict(record, created_at=row[0] if row else None, updated_at=row[1] if row else None)
    return dict(record, wall_clock_timestamp=row[0] if row else None)
