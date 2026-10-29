"""Pure per-detection scoring. No clock, history, correlation, or storage."""

from copy import deepcopy
from pathlib import Path
import yaml

if __package__:
    from .alerts import Alert, ScoreModifier, severity_for_score
    from .rule_config import RuleConfigError, _UniqueSafeLoader, _integer, MAX_CONFIG_BYTES, TYPE_CATEGORIES
else:
    from alerts import Alert, ScoreModifier, severity_for_score
    from rule_config import RuleConfigError, _UniqueSafeLoader, _integer, MAX_CONFIG_BYTES, TYPE_CATEGORIES

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "config/scoring.yaml"


def validate_policy(document):
    if not isinstance(document, dict) or set(document) != {"schema_version", "scoring"}:
        raise RuleConfigError("expected scoring schema_version and scoring")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RuleConfigError("unsupported scoring schema_version")
    policy = document["scoring"]
    if not isinstance(policy, dict) or set(policy) != set(TYPE_CATEGORIES):
        raise RuleConfigError("scoring requires exactly the six supported rule families")
    for family, config in policy.items():
        network = TYPE_CATEGORIES[family] == "network"
        expected = {"base_score"} | ({"tiers"} if family == "port_scan" else {"volume_tiers"} if network else
                                   {"root_uid_points"} if family == "privilege_change" else set())
        if not isinstance(config, dict) or set(config) != expected:
            raise RuleConfigError(f"invalid scoring fields for {family}")
        _integer(config["base_score"], 0, 100, "base_score")
        if family == "privilege_change":
            _integer(config["root_uid_points"], -100, 100, "root_uid_points")
        if family == "port_scan":
            previous_score = _integer(config["base_score"], 20, 49, "port_scan base_score")
            tiers = config["tiers"]
            if not isinstance(tiers, list) or not 1 <= len(tiers) <= 8:
                raise RuleConfigError("port_scan tiers must contain one to eight entries")
            previous_ports = 1
            for tier in tiers:
                if not isinstance(tier, dict) or set(tier) != {"min_unique_ports", "score"}:
                    raise RuleConfigError("invalid port_scan tier fields")
                ports = _integer(tier["min_unique_ports"], 2, 65535, "min_unique_ports")
                score = _integer(tier["score"], 20, 49, "port_scan tier score")
                if ports <= previous_ports or score < previous_score:
                    raise RuleConfigError("port_scan thresholds must increase and scores must not decrease")
                previous_ports, previous_score = ports, score
        elif network:
            tiers = config["volume_tiers"]
            if not isinstance(tiers, list) or len(tiers) > 8:
                raise RuleConfigError("volume_tiers must be a list of at most eight tiers")
            previous = 1
            for tier in tiers:
                if not isinstance(tier, dict) or set(tier) != {"multiple", "points"}:
                    raise RuleConfigError("invalid volume tier fields")
                multiple = _integer(tier["multiple"], 2, 1000, "multiple")
                _integer(tier["points"], -100, 100, "points")
                if multiple <= previous:
                    raise RuleConfigError("volume tier multiples must strictly increase")
                previous = multiple
    return deepcopy(policy)


class Scorer:
    def __init__(self, document):
        self._policy = validate_policy(document)

    @classmethod
    def from_file(cls, path=None):
        with Path(path if path is not None else DEFAULT_POLICY).open("rb") as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise RuleConfigError("scoring configuration too large")
        try:
            return cls(yaml.load(data.decode("utf-8"), Loader=_UniqueSafeLoader))
        except (yaml.YAMLError, UnicodeError, RecursionError) as error:
            raise RuleConfigError("invalid scoring YAML") from error

    def alert(self, *, alert_type, metadata, base_override=None, **fields):
        """Score finalized evidence and construct the only outward Alert model."""
        if alert_type not in self._policy:
            raise ValueError("unsupported scoring family")
        config = self._policy[alert_type]
        base = config["base_score"] if base_override is None else base_override
        if type(base) is not int or not 0 <= base <= 100:
            raise ValueError("invalid scoring base override")
        modifiers = []
        if alert_type == "port_scan":
            if base != config["base_score"]:
                raise ValueError("port_scan base override must equal configured base_score")
            count, threshold = metadata.get("unique_port_count"), metadata.get("threshold")
            if type(count) is not int or not 1 <= count <= 65535 or type(threshold) is not int or threshold < 1:
                raise ValueError("invalid port_scan count or threshold")
            selected_index = None
            for index, tier in enumerate(config["tiers"]):
                if count >= tier["min_unique_ports"]:
                    selected_index = index
            if selected_index is not None:
                tier = config["tiers"][selected_index]
                upper = (str(config["tiers"][selected_index + 1]["min_unique_ports"] - 1)
                         if selected_index + 1 < len(config["tiers"]) else None)
                label = f"{tier['min_unique_ports']}-{upper}" if upper else f"{tier['min_unique_ports']}+"
                modifiers.append(ScoreModifier("port_scan_scope", tier["score"] - base,
                    f"unique_port_count={count} falls in the {label} port tier"))
        elif "volume_tiers" in config:
            field = "matching_event_count"
            count, threshold = metadata.get(field), metadata.get("threshold")
            if type(count) is not int or count < 1 or type(threshold) is not int or threshold < 1:
                raise ValueError("scoring requires positive integer volume and threshold")
            selected = None
            for tier in config["volume_tiers"]:
                if count >= threshold * tier["multiple"]:
                    selected = tier
            if selected is not None:
                modifiers.append(ScoreModifier("volume", selected["points"],
                    f"{field}={count} meets {selected['multiple']}x threshold={threshold}"))
        if alert_type == "privilege_change":
            uid, previous = metadata.get("uid"), metadata.get("previous_uid")
            if type(uid) is not int or type(previous) is not int or not 0 <= uid < 2**32 or not 0 <= previous < 2**32:
                raise ValueError("privilege scoring requires current and previous UID")
            if uid == 0 and previous != 0:
                modifiers.append(ScoreModifier("uid_to_root", config["root_uid_points"],
                                               f"effective UID changed from {previous} to 0"))
        score = max(0, min(100, base + sum(item.points for item in modifiers)))
        return Alert(**fields, alert_type=alert_type, metadata=deepcopy(metadata),
                     risk_score=score, base_score=base, score_modifiers=tuple(modifiers),
                     severity=severity_for_score(score))
