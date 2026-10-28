"""Strict, versioned YAML rule configuration. No executable YAML tags."""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

import yaml

if __package__:
    from .alerts import SEVERITIES
else:
    from alerts import SEVERITIES

MAX_CONFIG_BYTES = 262144
MAX_RULES = 128
MAX_THRESHOLD = 4096
TYPE_CATEGORIES = {
    "port_scan": "network", "syn_flood": "network", "traffic_flood": "network",
    "process_match": "process", "syscall_match": "syscall", "privilege_change": "privilege",
}
MATCH_FIELDS = {
    "process_match": {"process_name", "process_path"},
    "syscall_match": {"syscall", "syscall_return", "uid", "gid", "process_name"},
    "privilege_change": {"syscall", "uid", "gid", "previous_uid", "previous_gid",
                         "process_name", "uid_changed", "gid_changed"},
}


class RuleConfigError(ValueError):
    """Invalid document or rule; configuration is rejected atomically."""


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise RuleConfigError("YAML keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuleConfigError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _duration(value, name):
    if type(value) not in (int, float):
        raise RuleConfigError(f"{name} must be a number")
    try:
        nanos = Decimal(str(value)) * 1_000_000_000
        if not nanos.is_finite() or not 1 <= nanos <= 86400 * 1_000_000_000 or nanos != nanos.to_integral_value():
            raise RuleConfigError(f"{name} must represent 1ns through 86400s")
    except InvalidOperation as error:
        raise RuleConfigError(f"invalid {name}") from error
    return int(nanos)


def _text(value, name, maximum=1024):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\0" in value:
        raise RuleConfigError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    enabled: bool
    category: str
    type: str
    severity: str
    description: str
    match: Mapping[str, tuple[str | int, ...] | bool]
    threshold: int = 0
    window_ns: int = 0
    max_groups: int = 0
    quiet_ns: int = 3_000_000_000
    max_detection_ns: int = 60_000_000_000
    max_event_ids: int = 64


def _parse_rule(raw):
    if not isinstance(raw, dict):
        raise RuleConfigError("each rule must be an object")
    common = {"id", "name", "enabled", "category", "type", "severity", "description"}
    if not common <= raw.keys():
        raise RuleConfigError("rule missing required fields")
    rule_type = _text(raw["type"], "type")
    if rule_type not in TYPE_CATEGORIES or raw["category"] != TYPE_CATEGORIES[rule_type]:
        raise RuleConfigError("unsupported rule category/type")
    rule_id = _text(raw["id"], "id", 100)
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", rule_id) is None:
        raise RuleConfigError("invalid rule ID")
    if type(raw["enabled"]) is not bool:
        raise RuleConfigError("enabled must be a boolean")
    if raw["severity"] not in SEVERITIES:
        raise RuleConfigError("invalid static severity")
    values = {key: raw[key] for key in common}
    values["name"] = _text(raw["name"], "name", 200)
    values["description"] = _text(raw["description"], "description")
    network = raw["category"] == "network"
    allowed = common | ({"threshold", "window_seconds", "max_groups", "quiet_seconds",
                         "max_detection_seconds", "max_event_ids"} if network else {"match"})
    if raw.keys() - allowed:
        raise RuleConfigError("unknown rule fields")
    if network:
        threshold = _integer(raw.get("threshold"), 1, MAX_THRESHOLD, "threshold")
        window_ns = _duration(raw.get("window_seconds"), "window_seconds")
        quiet_ns = _duration(raw.get("quiet_seconds", 3), "quiet_seconds")
        maximum_ns = _duration(raw.get("max_detection_seconds", 60), "max_detection_seconds")
        # Keep the configured session horizon at least as long as either the
        # confirmation window or the intended quiet period. Compare integer ns.
        if maximum_ns < max(window_ns, quiet_ns):
            raise RuleConfigError(
                "max_detection_seconds must be >= window_seconds and quiet_seconds")
        return Rule(
            **values, match=MappingProxyType({}), threshold=threshold,
            window_ns=window_ns,
            max_groups=_integer(raw.get("max_groups", 128), 1, 4096, "max_groups"),
            quiet_ns=quiet_ns, max_detection_ns=maximum_ns,
            max_event_ids=_integer(raw.get("max_event_ids", 64), 2, 256, "max_event_ids"))
    match = raw.get("match")
    if not isinstance(match, dict) or not match or match.keys() - MATCH_FIELDS[rule_type]:
        raise RuleConfigError("invalid or empty host match conditions")
    parsed = {}
    for key, condition in match.items():
        if key in ("uid_changed", "gid_changed"):
            if type(condition) is not bool:
                raise RuleConfigError(f"{key} must be a boolean")
            parsed[key] = condition
            continue
        if not isinstance(condition, list) or not 1 <= len(condition) <= 256:
            raise RuleConfigError(f"{key} must be a nonempty list with at most 256 entries")
        for value in condition:
            if key == "syscall_return":
                _integer(value, -(1 << 63), (1 << 63) - 1, key)
            elif key in ("uid", "gid", "previous_uid", "previous_gid"):
                _integer(value, 0, (1 << 32) - 1, key)
            else:
                _text(value, key, 255)
                if key == "syscall" and value not in ("setuid", "setgid"):
                    raise RuleConfigError("unsupported monitored syscall")
                if key == "process_name" and len(value) > 15:
                    raise RuleConfigError("process_name exceeds sensor limit")
        parsed[key] = tuple(condition)
    if rule_type == "syscall_match" and "syscall" not in parsed:
        raise RuleConfigError("syscall_match requires syscall selectors")
    if rule_type == "privilege_change" and not parsed.keys() & {
            "uid", "gid", "previous_uid", "previous_gid", "uid_changed", "gid_changed"}:
        raise RuleConfigError("privilege_change requires a credential condition")
    return Rule(**values, match=MappingProxyType(parsed))


def parse_rules(document):
    if not isinstance(document, dict) or set(document) != {"schema_version", "rules"}:
        raise RuleConfigError("expected schema_version and rules")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RuleConfigError("unsupported rule schema_version")
    raw_rules = document["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise RuleConfigError(f"rules must be a list with at most {MAX_RULES} rules")
    rules, seen = [], set()
    for position, raw in enumerate(raw_rules):
        try:
            rule = _parse_rule(raw)
            if rule.id in seen:
                raise RuleConfigError(f"duplicate rule ID: {rule.id}")
        except RuleConfigError as error:
            raise RuleConfigError(f"rule {position + 1}: {error}") from error
        seen.add(rule.id)
        rules.append(rule)
    return tuple(rules)


def load_rules(path):
    """Load a bounded local YAML file, rejecting ambiguous/malformed rules."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise RuleConfigError("rule configuration too large")
    try:
        document = yaml.load(data.decode("utf-8"), Loader=_UniqueSafeLoader)
        return parse_rules(document)
    except (yaml.YAMLError, UnicodeError, RecursionError) as error:
        raise RuleConfigError(f"invalid rule YAML: {error}") from error
