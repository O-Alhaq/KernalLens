"""Validated M9 scoring output and explainable score contributions."""

from dataclasses import asdict, dataclass, field
import json
from uuid import UUID, uuid4

def severity_for_score(score):
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("risk_score must be an integer in [0, 100]")
    return "low" if score < 20 else "medium" if score < 50 else "high" if score < 80 else "critical"


@dataclass(frozen=True)
class ScoreModifier:
    name: str
    points: int
    reason: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name or not isinstance(self.reason, str) or not self.reason:
            raise ValueError("modifier requires a name and reason")
        if type(self.points) is not int or not -100 <= self.points <= 100:
            raise ValueError("invalid modifier points")


@dataclass(frozen=True, kw_only=True)
class Alert:
    timestamp: int
    rule_id: str
    rule_name: str
    alert_type: str
    severity: str
    risk_score: int
    base_score: int
    score_modifiers: tuple[ScoreModifier, ...] = ()
    description: str
    source_event_ids: tuple[str, ...]
    event_category: str
    metadata: dict = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self):
        try:
            identifier = UUID(self.alert_id)
            if identifier.version != 4 or str(identifier) != self.alert_id:
                raise ValueError("alert_id must be a canonical UUID4")
            if not isinstance(self.source_event_ids, tuple) or not self.source_event_ids:
                raise ValueError("source_event_ids must be a nonempty tuple")
            for value in self.source_event_ids:
                event_id = UUID(value)
                if event_id.version != 4 or str(event_id) != value:
                    raise ValueError("invalid source event UUID4")
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("invalid alert/source event ID") from error
        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("duplicate source event IDs")
        if type(self.timestamp) is not int or not 0 <= self.timestamp < (1 << 64):
            raise ValueError("invalid alert timestamp")
        for value in (self.rule_id, self.rule_name, self.alert_type, self.description):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("alert rule/type/description fields must be nonempty strings")
        if self.severity != severity_for_score(self.risk_score):
            raise ValueError("severity does not match risk_score")
        if type(self.base_score) is not int or not 0 <= self.base_score <= 100:
            raise ValueError("invalid base_score")
        if not isinstance(self.score_modifiers, tuple) or any(
                not isinstance(item, ScoreModifier) for item in self.score_modifiers):
            raise ValueError("invalid score_modifiers")
        if self.risk_score != max(0, min(100, self.base_score + sum(item.points for item in self.score_modifiers))):
            raise ValueError("risk_score does not match scoring evidence")
        if self.event_category not in ("network", "process", "syscall", "privilege"):
            raise ValueError("invalid alert category")
        if type(self.metadata) is not dict:
            raise ValueError("alert metadata must be an object")
        try:
            json.dumps(self.metadata, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("alert metadata must be JSON compatible") from error

    def to_dict(self):
        value = asdict(self)
        value["source_event_ids"] = list(self.source_event_ids)
        value["score_modifiers"] = [asdict(item) for item in self.score_modifiers]
        return value
