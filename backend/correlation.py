"""Deterministic M10 correlation of finalized M9 Alerts. No I/O or clocks."""

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
from ipaddress import IPv4Address
import logging

if __package__:
    from .alerts import Alert, severity_for_score
    from .correlation_config import load_policy, parse_policy
    from .incidents import Incident
    from .rule_config import TYPE_CATEGORIES
else:
    from alerts import Alert, severity_for_score
    from correlation_config import load_policy, parse_policy
    from incidents import Incident
    from rule_config import TYPE_CATEGORIES

logger = logging.getLogger(__name__)
NETWORK = {"port_scan", "syn_flood", "traffic_flood"}
HOST = {"process_match", "syscall_match", "privilege_change"}


@dataclass
class _Evidence:
    alert_id: str
    timestamp: int
    alert_type: str
    risk_score: int
    src_ip: str | None
    dst_ip: str | None
    pid: int | None
    root_change: bool
    used: set = field(default_factory=set)


@dataclass
class _Group:
    entities: dict
    evidence: list
    incident_id: str | None = None

    @property
    def first(self):
        return min(item.timestamp for item in self.evidence)


class CorrelationEngine:
    """Single serial host/boot stream. evaluate returns new/updated snapshots.

    __call__ also publishes, containing failures. Windows include both endpoints;
    old input is accepted only within the watermark's retained window. Incident
    span never exceeds its rule window. Each alert participates at most once per
    correlation family (hybrid ties choose the lexicographically first context).
    UUID4 identities are random; grouping, evidence and risk are deterministic.
    """

    def __init__(self, document=None):
        self._initialize(load_policy() if document is None else parse_policy(document))

    def _initialize(self, policy):
        self.policy = policy
        self._rules = {rule.name: rule for rule in self.policy.rules if rule.enabled}
        self._horizon = max((rule.window_ns for rule in self._rules.values()), default=0)
        self._watermark = 0
        self._pending = OrderedDict()
        self._open = OrderedDict()
        self._seen = OrderedDict()
        self._subscribers = []

    @classmethod
    def from_file(cls, path):
        result = cls.__new__(cls)
        result._initialize(load_policy(path))
        return result

    @property
    def state_counts(self):
        return {"pending_alerts": len(self._pending), "open_incidents": len(self._open),
                "seen_alerts": len(self._seen),
                "incident_alert_references": sum(len(group.evidence) for group in self._open.values())}

    def advance_time(self, timestamp):
        """Expire state only. No delayed incident emission or system-clock reads."""
        if type(timestamp) is not int or not 0 <= timestamp < 2**64:
            raise ValueError("invalid correlation timestamp")
        self._watermark = max(self._watermark, timestamp)
        for key, group in list(self._open.items()):
            if group.first + self._rules[key[0]].window_ns < self._watermark:
                del self._open[key]
        for mapping in (self._pending, self._seen):
            for key, value in list(mapping.items()):
                timestamp = value.timestamp if isinstance(value, _Evidence) else value
                if timestamp + self._horizon < self._watermark:
                    del mapping[key]

    @staticmethod
    def _summary(alert):
        if not isinstance(alert, Alert):
            raise ValueError("correlation requires a finalized Alert")
        # Frozen dataclasses still contain mutable metadata: revalidate a copy.
        alert = deepcopy(alert)
        alert.__post_init__()
        if TYPE_CATEGORIES.get(alert.alert_type) != alert.event_category:
            return None
        metadata = alert.metadata
        src, dst, pid = None, None, None
        if alert.alert_type in NETWORK:
            try:
                for name in ("src_ip", "dst_ip"):
                    value = metadata.get(name)
                    if not isinstance(value, str) or str(IPv4Address(value)) != value or value == "0.0.0.0":
                        return None
                src, dst = metadata["src_ip"], metadata["dst_ip"]
            except ValueError:
                return None
        else:
            pid = metadata.get("pid")
            if type(pid) is not int or not 1 <= pid < 2**32:
                return None
        previous, uid, result = (metadata.get(key) for key in ("previous_uid", "uid", "syscall_return"))
        root = (alert.alert_type == "privilege_change" and type(previous) is int
                and 0 < previous < 2**32 and type(uid) is int and uid == 0
                and type(result) is int and result == 0 and alert.risk_score >= 50)
        return _Evidence(alert.alert_id, alert.timestamp, alert.alert_type, alert.risk_score, src, dst, pid, root)

    def _hybrid_network(self, item):
        return (item.alert_type in ("syn_flood", "traffic_flood") and item.risk_score >= 50
                and item.dst_ip in self.policy.monitored_ips)

    def _keys(self, family, item):
        if family == "network_sequence":
            return [(item.src_ip, item.dst_ip)] if item.alert_type in NETWORK else []
        if family == "host_sequence":
            return [(item.pid,)] if item.alert_type in HOST else []
        keys = set()
        if self._hybrid_network(item):
            keys.update((item.src_ip, item.dst_ip, other.pid) for other in self._pending.values()
                        if other.root_change and family not in other.used)
            keys.update(key[1:] for key in self._open if key[0] == family and key[1:3] == (item.src_ip, item.dst_ip))
        elif item.root_change:
            keys.update((other.src_ip, other.dst_ip, item.pid) for other in self._pending.values()
                        if self._hybrid_network(other) and family not in other.used)
            keys.update(key[1:] for key in self._open if key[0] == family and key[3] == item.pid)
        return sorted(keys)

    def _matches(self, family, key, item):
        if family == "network_sequence":
            return item.alert_type in NETWORK and (item.src_ip, item.dst_ip) == key
        if family == "host_sequence":
            return item.alert_type in HOST and (item.pid,) == key
        return ((self._hybrid_network(item) and (item.src_ip, item.dst_ip) == key[:2])
                or (item.root_change and item.pid == key[2]))

    def _snapshot(self, family, group):
        ordered = sorted(group.evidence, key=lambda item: (item.timestamp, item.alert_id))
        highest = max(item.risk_score for item in ordered)
        score = min(100, highest + 5)
        hybrid = family == "hybrid_activity"
        description = ("Flood activity against a configured local IP and a successful root transition are "
                       "temporally/contextually related. This does not establish process-to-network attribution."
                       if hybrid else "Different detection types share the same " +
                       ("source/destination IP pair" if family == "network_sequence" else "PID") +
                       " within the configured correlation window.")
        data = dict(created_timestamp=ordered[0].timestamp, updated_timestamp=ordered[-1].timestamp,
                    incident_type=family, title=family.replace("_", " ").title(), description=description,
                    severity=severity_for_score(score), risk_score=score,
                    alert_ids=tuple(item.alert_id for item in ordered), primary_entities=deepcopy(group.entities),
                    metadata={"correlation_rule": family, "correlation_window_ns": self._rules[family].window_ns,
                              "relationship": "temporal_contextual" if hybrid else "shared_entities",
                              "exact_process_network_attribution": False,
                              "shared_entities": ({"monitored_ip": group.entities["dst_ip"]} if hybrid else deepcopy(group.entities)),
                              "alert_types": sorted({item.alert_type for item in ordered}),
                              "highest_alert_score": highest, "correlation_points": 5,
                              "score_reason": "Highest member alert score plus 5 for corroborating detections",
                              "alert_limit_reached": len(ordered) == self.policy.max_alerts_per_incident})
        if group.incident_id is not None:
            data["incident_id"] = group.incident_id
        result = Incident(**data)
        group.incident_id = result.incident_id
        return result

    def _evaluate_rule(self, family, item):
        rule = self._rules[family]
        if item.timestamp < self._watermark - rule.window_ns:
            return None
        for key in self._keys(family, item):
            identity = (family, *key)
            group = self._open.get(identity)
            if group is not None:
                # Replays are suppressed even after the global replay cache evicts an ID.
                if any(other.alert_id == item.alert_id for other in group.evidence):
                    return None
                if (len(group.evidence) >= self.policy.max_alerts_per_incident
                        or max(item.timestamp, max(other.timestamp for other in group.evidence))
                        - min(item.timestamp, group.first) > rule.window_ns):
                    item.used.add(family)
                    return None
                group.evidence.append(item)
            else:
                if len(self._open) >= self.policy.max_open_incidents:
                    return None
                candidates = sorted((other for other in self._pending.values()
                                     if family not in other.used and other.alert_id != item.alert_id
                                     and other.timestamp >= self._watermark - rule.window_ns
                                     and self._matches(family, key, other)),
                                    key=lambda other: (other.timestamp, other.alert_id))
                partner = next((other for other in candidates if other.alert_type != item.alert_type
                                and (family != "hybrid_activity" or other.root_change != item.root_change)), None)
                if partner is None:
                    continue
                members = [partner, item]
                members.extend(other for other in candidates if other is not partner)
                members = members[:self.policy.max_alerts_per_incident]
                names = ("src_ip", "dst_ip") if family == "network_sequence" else ("pid",) if family == "host_sequence" else ("src_ip", "dst_ip", "pid")
                group = _Group(dict(zip(names, key)), members)
                self._open[identity] = group
                # Even overflow candidates cannot reopen this sequence after expiry.
                for other in candidates:
                    other.used.add(family)
            for other in group.evidence:
                other.used.add(family)
            return self._snapshot(family, group)
        return None

    def evaluate(self, alert):
        item = self._summary(alert)
        self.advance_time(alert.timestamp)
        if item is None or not self._rules or item.timestamp < self._watermark - self._horizon:
            return []
        if item.alert_id in self._seen or item.alert_id in self._pending or any(
                any(other.alert_id == item.alert_id for other in group.evidence) for group in self._open.values()):
            return []
        self._seen[item.alert_id] = item.timestamp
        if len(self._seen) > self.policy.max_seen_alerts:
            self._seen.popitem(last=False)
        results = []
        for family in self._rules:
            try:
                result = self._evaluate_rule(family, item)
                if result is not None:
                    results.append(result)
            except Exception:
                logger.exception("Correlation rule %s failed for alert %s", family, item.alert_id)
        self._pending[item.alert_id] = item
        if len(self._pending) > self.policy.max_pending_alerts:
            oldest = min(self._pending, key=lambda key: (self._pending[key].timestamp, key))
            del self._pending[oldest]
        return results

    def subscribe(self, consumer):
        if not callable(consumer):
            raise ValueError("incident subscriber must be callable")
        self._subscribers.append(consumer)

    def __call__(self, alert):
        try:
            results = self.evaluate(alert)
            for incident in results:
                for consumer in tuple(self._subscribers):
                    try:
                        consumer(deepcopy(incident))
                    except Exception:
                        logger.exception("Incident subscriber failed for %s", incident.incident_id)
            return results
        except Exception:
            logger.exception("Correlation failed; continuing alert pipeline")
            return []
