"""M11 transactional change references and constant-size summary counters."""

import json

if __package__:
    from .operator_time import project
else:
    from operator_time import project

if __package__:
    from .storage import EventStore
else:
    from storage import EventStore

FAMILIES = {"event": "events", "alert": "alerts", "incident": "incidents"}
JOURNAL_PER_FAMILY = 512
BATCH_PER_FAMILY = 128


def migrate_dashboard(connection):
    connection.execute("ALTER TABLE incidents ADD COLUMN live_sequence INTEGER NOT NULL DEFAULT 0")
    connection.execute("CREATE INDEX incidents_live_sequence ON incidents(live_sequence)")
    connection.execute("CREATE TABLE live_changes (sequence INTEGER PRIMARY KEY AUTOINCREMENT, family TEXT NOT NULL, object_id TEXT NOT NULL)")
    connection.execute("CREATE INDEX live_family ON live_changes(family, sequence)")
    connection.execute("CREATE INDEX live_object ON live_changes(family, object_id, sequence)")
    connection.execute("CREATE TABLE dashboard_counts (name TEXT PRIMARY KEY, value INTEGER NOT NULL)")
    connection.execute("CREATE TABLE live_pruned (family TEXT PRIMARY KEY, through_sequence INTEGER NOT NULL)")
    for family, table in FAMILIES.items():
        identifier = f"{family}_id"
        connection.execute("INSERT INTO dashboard_counts VALUES (?, ?)",
                           (table, connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]))
        connection.execute("INSERT INTO live_pruned VALUES (?, 0)", (family,))
        if family != "event":
            severity = "json_extract(record, '$.severity')" if family == "alert" else "severity"
            for level in ("low", "medium", "high", "critical"):
                count = connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {severity}=?", (level,)).fetchone()[0]
                connection.execute("INSERT INTO dashboard_counts VALUES (?, ?)", (f"{table}_{level}", count))
        for action in (["INSERT", "UPDATE"] if family == "incident" else ["INSERT"]):
            # Keep small ID-only journals; no duplicate serialized evidence on disk.
            body = f"""
                INSERT INTO live_changes(family, object_id) VALUES ('{family}', NEW.{identifier});
                UPDATE live_pruned SET through_sequence=MAX(through_sequence, COALESCE(
                    (SELECT sequence FROM live_changes WHERE family='{family}' ORDER BY sequence DESC LIMIT 1 OFFSET {JOURNAL_PER_FAMILY}), 0))
                    WHERE family='{family}';
                DELETE FROM live_changes WHERE family='{family}' AND sequence <=
                    (SELECT through_sequence FROM live_pruned WHERE family='{family}');
            """
            if family == "incident":
                body += """UPDATE incidents SET live_sequence=(SELECT MAX(sequence) FROM live_changes
                    WHERE family='incident' AND object_id=NEW.incident_id) WHERE incident_id=NEW.incident_id;"""
            if action == "INSERT":
                body += f"UPDATE dashboard_counts SET value=value+1 WHERE name='{table}';"
                if family != "event":
                    body += f"UPDATE dashboard_counts SET value=value+1 WHERE name='{table}_' || json_extract(NEW.record, '$.severity');"
            else:
                body += """UPDATE dashboard_counts SET value=value-1 WHERE name='incidents_' || OLD.severity;
                    UPDATE dashboard_counts SET value=value+1 WHERE name='incidents_' || NEW.severity;"""
            condition = " WHEN OLD.record != NEW.record" if action == "UPDATE" else ""
            connection.execute(f"CREATE TRIGGER live_{family}_{action.lower()} AFTER {action} ON {table}{condition} BEGIN {body} END")
    for field in ("severity", "alert_type", "event_category"):
        connection.execute(f"CREATE INDEX alerts_{field} ON alerts(json_extract(record, '$.{field}'))")


class DashboardStore(EventStore):
    @staticmethod
    def _cursor(connection):
        row = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='live_changes'").fetchone()
        return row[0] if row else 0

    @staticmethod
    def _summary(connection):
        values = dict(connection.execute("SELECT name, value FROM dashboard_counts"))
        return {**{f"total_{name}": values[name] for name in FAMILIES.values()},
                **{f"{name}_by_severity": {level: values[f"{name}_{level}"] for level in
                    ("low", "medium", "high", "critical")} for name in ("alerts", "incidents")}}

    def summary(self):
        with self._connection() as connection:
            return self._summary(connection)

    def snapshot(self):
        with self._connection() as connection:
            connection.execute("BEGIN")
            result = {"cursor": self._cursor(connection), "summary": self._summary(connection)}
            for family, table in FAMILIES.items():
                limit = 50 if family == "incident" else 100
                order = "live_sequence DESC, rowid DESC" if family == "incident" else "rowid DESC"
                rows = connection.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT ?", (limit,)).fetchall()
                result[table] = [project(connection, family, self._decode(row).to_dict() if family == "event" else json.loads(row["record"])) for row in rows]
            return result

    def changes(self, cursors):
        """One bounded read transaction per poll; return snapshots from committed rows."""
        with self._connection() as connection:
            connection.execute("BEGIN")
            end = self._cursor(connection)
            messages, updated, gap = [], {}, False
            for family, table in FAMILIES.items():
                cursor = cursors.get(family, 0)
                pruned = connection.execute("SELECT through_sequence FROM live_pruned WHERE family=?", (family,)).fetchone()[0]
                gap = gap or cursor < pruned
                rows = connection.execute("SELECT sequence, object_id FROM live_changes WHERE family=? AND sequence>? ORDER BY sequence LIMIT ?",
                                          (family, cursor, BATCH_PER_FAMILY)).fetchall()
                updated[family] = rows[-1]["sequence"] if rows else max(cursor, pruned)
                for row in rows:
                    record = connection.execute(f"SELECT * FROM {table} WHERE {family}_id=?", (row["object_id"],)).fetchone()
                    if record is not None:
                        data = project(connection, family, self._decode(record).to_dict() if family == "event" else json.loads(record["record"]))
                        # Immutable rows use their original change sequence. Incident
                        # references resolve to the current snapshot and its revision.
                        revision = row["sequence"]
                        if family == "incident":
                            revision = connection.execute(
                                "SELECT MAX(sequence) FROM live_changes WHERE family='incident' AND object_id=?",
                                (row["object_id"],)).fetchone()[0]
                        messages.append({"schema_version": 1, "message_type": family,
                                         "sequence": revision, "data": data})
            return messages, updated, gap, {"schema_version": 1, "message_type": "status", "sequence": end,
                                            "data": {"database": "ok", "summary": self._summary(connection), "resync_required": gap}}

    def operator_record(self, family, record):
        return self.operator_records(family, [record])[0]

    def operator_records(self, family, records):
        # One connection and read transaction for each bounded REST collection.
        with self._connection() as connection:
            connection.execute("BEGIN")
            result = []
            for record in records:
                if family == "incident":
                    # Read mutable evidence and its clocks from the same snapshot.
                    row = connection.execute("SELECT record FROM incidents WHERE incident_id=?",
                                             (record["incident_id"],)).fetchone()
                    if row is not None:
                        record = json.loads(row[0])
                result.append(project(connection, family, record))
            return result
