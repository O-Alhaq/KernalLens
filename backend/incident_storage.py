"""Minimal M10 persistence subscribers using the existing SQLite lifecycle."""

from copy import deepcopy
import json

if __package__:
    from .alerts import Alert, ScoreModifier
    from .incidents import Incident
    from .storage import EventStore, validate_pagination
else:
    from alerts import Alert, ScoreModifier
    from incidents import Incident
    from storage import EventStore, validate_pagination


def _encode(value):
    return json.dumps(value.to_dict(), allow_nan=False, sort_keys=True, separators=(",", ":"))


class IncidentStore(EventStore):
    """Persist Alerts before incident callbacks. Errors propagate to the caller.

    Alerts are immutable records; identical replay is idempotent, conflicting IDs
    are rejected. Incident snapshots update atomically with their foreign-key links.
    This stores output, not correlation state; startup never replays old Alerts.
    """

    def insert_alert(self, alert):
        if not isinstance(alert, Alert):
            raise ValueError("alert storage requires an Alert")
        alert = deepcopy(alert)
        alert.__post_init__()
        record = _encode(alert)
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute("SELECT record FROM alerts WHERE alert_id=?", (alert.alert_id,)).fetchone()
            if previous is not None:
                if previous[0] != record:
                    raise ValueError("conflicting immutable Alert ID")
                return
            connection.execute("INSERT INTO alerts VALUES (?, ?)", (alert.alert_id, record))

    def get_alert(self, alert_id):
        with self._connection() as connection:
            row = connection.execute("SELECT record FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        if row is None:
            return None
        data = json.loads(row[0])
        data["source_event_ids"] = tuple(data["source_event_ids"])
        data["score_modifiers"] = tuple(ScoreModifier(**item) for item in data["score_modifiers"])
        return Alert(**data)

    def save_incident(self, incident):
        if not isinstance(incident, Incident):
            raise ValueError("incident storage requires an Incident")
        incident = Incident.from_dict(incident.to_dict())
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute("SELECT record FROM incidents WHERE incident_id=?", (incident.incident_id,)).fetchone()
            if previous is not None:
                old = Incident.from_dict(json.loads(previous[0]))
                if (old.incident_type != incident.incident_type or old.primary_entities != incident.primary_entities
                        or not set(old.alert_ids) <= set(incident.alert_ids)
                        or old.updated_timestamp > incident.updated_timestamp
                        or old.created_timestamp < incident.created_timestamp
                        or old.risk_score > incident.risk_score):
                    raise ValueError("conflicting or stale incident update")
            connection.execute("""INSERT INTO incidents (incident_id, incident_type, severity, record) VALUES (?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET severity=excluded.severity, record=excluded.record""",
                (incident.incident_id, incident.incident_type, incident.severity, _encode(incident)))
            connection.executemany("INSERT OR IGNORE INTO incident_alerts VALUES (?, ?)",
                                   ((incident.incident_id, alert_id) for alert_id in incident.alert_ids))

    def get_incident(self, incident_id):
        with self._connection() as connection:
            row = connection.execute("SELECT record FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        return None if row is None else Incident.from_dict(json.loads(row[0]))

    def list_incidents(self, *, limit=100, offset=0, incident_type=None, severity=None, newest_first=False):
        validate_pagination(limit, offset)
        if type(newest_first) is not bool:
            raise ValueError("newest_first must be boolean")
        clauses, values = [], []
        for column, value in (("incident_type", incident_type), ("severity", severity)):
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{column} must be a string")
                clauses.append(f"{column}=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(f"SELECT record FROM incidents{where} ORDER BY rowid {'DESC' if newest_first else 'ASC'} LIMIT ? OFFSET ?",
                                      (*values, limit, offset)).fetchall()
        return [Incident.from_dict(json.loads(row[0])) for row in rows]

    def list_alerts(self, *, limit=100, offset=0, severity=None, event_category=None,
                    alert_type=None, newest_first=False):
        validate_pagination(limit, offset)
        if type(newest_first) is not bool:
            raise ValueError("newest_first must be boolean")
        clauses, values = [], []
        for field, value in (("severity", severity), ("event_category", event_category), ("alert_type", alert_type)):
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{field} must be a string")
                clauses.append(f"json_extract(record, '$.{field}')=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(f"SELECT record FROM alerts{where} ORDER BY rowid {'DESC' if newest_first else 'ASC'} LIMIT ? OFFSET ?",
                                      (*values, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]
