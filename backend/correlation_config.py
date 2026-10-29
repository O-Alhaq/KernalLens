"""Strict, bounded, versioned correlation policy; no executable YAML."""

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
import yaml

if __package__:
    from .incidents import INCIDENT_TYPES
    from .rule_config import RuleConfigError, _UniqueSafeLoader, _integer, _duration, MAX_CONFIG_BYTES
else:
    from incidents import INCIDENT_TYPES
    from rule_config import RuleConfigError, _UniqueSafeLoader, _integer, _duration, MAX_CONFIG_BYTES

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "config/correlation.yaml"
CorrelationConfigError = RuleConfigError


@dataclass(frozen=True)
class CorrelationRule:
    name: str
    enabled: bool
    window_ns: int


@dataclass(frozen=True)
class CorrelationPolicy:
    rules: tuple[CorrelationRule, ...]
    monitored_ips: tuple[str, ...]
    max_pending_alerts: int
    max_open_incidents: int
    max_alerts_per_incident: int
    max_seen_alerts: int


def parse_policy(document):
    if not isinstance(document, dict) or set(document) != {"schema_version", "correlation", "monitored_ips", "limits"}:
        raise RuleConfigError("expected correlation schema_version, correlation, monitored_ips and limits")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RuleConfigError("unsupported correlation schema_version")
    raw = document["correlation"]
    if not isinstance(raw, dict) or set(raw) != set(INCIDENT_TYPES):
        raise RuleConfigError("expected exactly three correlation families")
    rules = []
    for name in INCIDENT_TYPES:
        item = raw[name]
        if not isinstance(item, dict) or set(item) != {"enabled", "window_seconds"}:
            raise RuleConfigError("invalid correlation rule fields")
        if type(item["enabled"]) is not bool:
            raise RuleConfigError("enabled must be boolean")
        rules.append(CorrelationRule(name, item["enabled"], _duration(item["window_seconds"], "window_seconds")))
    ips = document["monitored_ips"]
    if not isinstance(ips, list) or len(ips) > 32:
        raise RuleConfigError("monitored_ips must be a list of at most 32 local IPv4 addresses")
    for value in ips:
        try:
            if (not isinstance(value, str) or str(IPv4Address(value)) != value
                    or IPv4Address(value).is_unspecified or IPv4Address(value).is_multicast
                    or value == "255.255.255.255"):
                raise ValueError("invalid local IP")
        except ValueError as error:
            raise RuleConfigError("invalid monitored IPv4 address") from error
    if len(set(ips)) != len(ips):
        raise RuleConfigError("duplicate monitored IP")
    limits = document["limits"]
    bounds = {"max_pending_alerts": (2, 16384), "max_open_incidents": (1, 4096),
              "max_alerts_per_incident": (2, 1024), "max_seen_alerts": (2, 65536)}
    if not isinstance(limits, dict) or set(limits) != set(bounds):
        raise RuleConfigError("invalid correlation limits")
    values = {key: _integer(limits[key], low, high, key) for key, (low, high) in bounds.items()}
    return CorrelationPolicy(tuple(rules), tuple(ips), **values)


def load_policy(path=None):
    with Path(path if path is not None else DEFAULT_POLICY).open("rb") as stream:
        data = stream.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise RuleConfigError("correlation configuration too large")
    try:
        return parse_policy(yaml.load(data.decode("utf-8"), Loader=_UniqueSafeLoader))
    except (yaml.YAMLError, UnicodeError, RecursionError) as error:
        raise RuleConfigError("invalid correlation YAML") from error
