"""Validated M10 incident snapshots, separate from telemetry and detections."""

from dataclasses import asdict, dataclass, field
import json
from uuid import UUID, uuid4

if __package__:
    from .alerts import severity_for_score
else:
    from alerts import severity_for_score

INCIDENT_TYPES = ("network_sequence", "host_sequence", "hybrid_activity")
MAX_INCIDENT_ALERTS = 1024


def validate_uuid(value):
    try:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError("expected canonical UUID4")
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("expected canonical UUID4") from error


@dataclass(frozen=True, kw_only=True)
class Incident:
    created_timestamp: int
    updated_timestamp: int
    incident_type: str
    title: str
    description: str
    severity: str
    risk_score: int
    alert_ids: tuple[str, ...]
    primary_entities: dict
    metadata: dict
    status: str = "open"
    incident_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self):
        validate_uuid(self.incident_id)
        for timestamp in (self.created_timestamp, self.updated_timestamp):
            if type(timestamp) is not int or not 0 <= timestamp < 2**64:
                raise ValueError("invalid incident timestamp")
        if self.updated_timestamp < self.created_timestamp:
            raise ValueError("incident timestamps are reversed")
        if self.incident_type not in INCIDENT_TYPES or self.status != "open":
            raise ValueError("invalid incident type/status")
        for value in (self.title, self.description):
            if not isinstance(value, str) or not value.strip() or len(value) > 2048:
                raise ValueError("invalid incident text")
        if self.severity != severity_for_score(self.risk_score):
            raise ValueError("incident severity does not match risk_score")
        if not isinstance(self.alert_ids, tuple) or not 2 <= len(self.alert_ids) <= MAX_INCIDENT_ALERTS:
            raise ValueError("incident requires two or more bounded alert references")
        for value in self.alert_ids:
            validate_uuid(value)
        if len(set(self.alert_ids)) != len(self.alert_ids):
            raise ValueError("duplicate incident alert IDs")
        for value in (self.primary_entities, self.metadata):
            if type(value) is not dict:
                raise ValueError("incident entities/metadata must be objects")
            try:
                encoded = json.dumps(value, allow_nan=False)
            except (TypeError, ValueError) as error:
                raise ValueError("incident evidence must be JSON compatible") from error
            if len(encoded.encode("utf-8")) > 65536:
                raise ValueError("incident evidence too large")
        highest, bonus = self.metadata.get("highest_alert_score"), self.metadata.get("correlation_points")
        severity_for_score(highest)
        if type(bonus) is not int or bonus != 5 or self.risk_score != min(100, highest + bonus):
            raise ValueError("incident score does not match evidence")
        window = self.metadata.get("correlation_window_ns")
        if (type(window) is not int or not 1 <= window <= 86400 * 10**9
                or self.updated_timestamp - self.created_timestamp > window
                or self.metadata.get("correlation_rule") != self.incident_type):
            raise ValueError("invalid incident correlation evidence")

    def to_dict(self):
        result = asdict(self)
        result["alert_ids"] = list(self.alert_ids)
        return result

    @classmethod
    def from_dict(cls, value):
        data = dict(value)
        if not isinstance(data.get("alert_ids"), (list, tuple)):
            raise ValueError("invalid incident alert IDs")
        data["alert_ids"] = tuple(data["alert_ids"])
        try:
            return cls(**data)
        except TypeError as error:
            raise ValueError("invalid incident fields") from error
