"""M8 deterministic user-space rules; no transport, database, or API dependency."""

from collections import OrderedDict
import logging

if __package__:
    from .alerts import Alert
    from .events import SecurityEvent
    from .rule_config import MAX_RULES, Rule
else:
    from alerts import Alert
    from events import SecurityEvent
    from rule_config import MAX_RULES, Rule

logger = logging.getLogger(__name__)


class _Runtime:
    def __init__(self, rule):
        self.rule = rule
        self.groups = OrderedDict()

    def _alert(self, timestamp, event_ids, metadata):
        rule = self.rule
        return Alert(timestamp=timestamp, rule_id=rule.id, rule_name=rule.name,
                     alert_type=rule.type, severity=rule.severity, description=rule.description,
                     source_event_ids=tuple(event_ids), event_category=rule.category,
                     metadata=metadata)

    def _expire(self, cutoff):
        for key, samples in list(self.groups.items()):
            for sample_key, (timestamp, _) in list(samples.items()):
                if timestamp <= cutoff:
                    del samples[sample_key]
            if not samples:
                del self.groups[key]

    def evaluate(self, event, watermark):
        rule = self.rule
        if rule.category != "network":
            return self._host(event)
        cutoff = watermark - rule.window_ns
        # Prune all groups even when this event belongs to an unrelated category.
        self._expire(cutoff)
        if event.event_category != "network" or event.timestamp <= cutoff:
            return None
        if event.protocol == "OTHER" or event.src_ip == "0.0.0.0" or event.dst_ip == "0.0.0.0":
            return None
        if rule.type in ("port_scan", "syn_flood"):
            # TCP connection attempts: SYN set, ACK clear. Ignore unavailable ports.
            if event.protocol != "TCP" or event.tcp_flags & 0x12 != 0x02 or not event.dst_port:
                return None
        key = (event.src_ip, event.dst_ip)
        if key not in self.groups:
            if len(self.groups) >= rule.max_groups:
                self.groups.popitem(last=False)
            self.groups[key] = {}
        samples = self.groups[key]
        self.groups.move_to_end(key)
        sample_key = event.dst_port if rule.type == "port_scan" else event.event_id
        previous = samples.get(sample_key)
        if previous is None or event.timestamp >= previous[0]:
            samples[sample_key] = (event.timestamp, event.event_id)
        if len(samples) < rule.threshold:
            return None
        ordered = sorted(samples.values(), key=lambda sample: sample[0])
        metadata = {"src_ip": key[0], "dst_ip": key[1], "count": len(samples),
                    "threshold": rule.threshold, "window_ns": rule.window_ns,
                    "first_timestamp": ordered[0][0], "last_timestamp": ordered[-1][0]}
        if rule.type == "port_scan":
            metadata["destination_ports"] = sorted(samples)
        # Reset before output construction, so a failed rule cannot accumulate
        # more than threshold samples in its group. No persistent alert cache.
        del self.groups[key]
        return self._alert(watermark, [event_id for _, event_id in ordered], metadata)

    def _host(self, event):
        rule = self.rule
        expected_types = {"process_match": "process_exec", "syscall_match": "syscall_event",
                          "privilege_change": "privilege_change"}
        if event.event_category != rule.category or event.event_type != expected_types[rule.type]:
            return None
        for key, condition in rule.match.items():
            if key in ("uid_changed", "gid_changed"):
                credential = key.removesuffix("_changed")
                changed = getattr(event, credential) != event.metadata[f"previous_{credential}"]
                if changed != condition:
                    return None
            else:
                value = event.metadata[key] if key in ("syscall_return", "previous_uid", "previous_gid") else getattr(event, key)
                if value not in condition:
                    return None
        metadata = {"pid": event.pid, "uid": event.uid, "gid": event.gid,
                    "process_name": event.process_name, "process_path": event.process_path,
                    "syscall": event.syscall, **event.metadata}
        return self._alert(event.timestamp, (event.event_id,), metadata)


class RuleEngine:
    """One serial event stream per engine. Use the engine itself as a subscriber.

    evaluate returns alerts. __call__ also publishes them to alert subscribers
    and isolates failures so detection cannot interrupt other pipeline consumers.
    Event-time windows use a nondecreasing high watermark. Late network events
    inside the window are accepted; events at/before its cutoff are ignored.
    """

    def __init__(self, rules):
        rules = tuple(rules)
        if len(rules) > MAX_RULES or any(not isinstance(rule, Rule) for rule in rules):
            raise ValueError("engine requires validated rules")
        if len({rule.id for rule in rules}) != len(rules):
            raise ValueError("duplicate rule IDs")
        self._runtimes = [_Runtime(rule) for rule in rules if rule.enabled]
        self._watermark = 0
        self._subscribers = []

    def subscribe(self, consumer):
        if not callable(consumer):
            raise ValueError("alert subscriber must be callable")
        self._subscribers.append(consumer)

    def evaluate(self, event):
        if not isinstance(event, SecurityEvent):
            raise ValueError("rule evaluation requires a SecurityEvent")
        # A validated snapshot protects the original event and nested metadata.
        snapshot = SecurityEvent.from_dict(event.to_dict())
        self._watermark = max(self._watermark, snapshot.timestamp)
        alerts = []
        for runtime in self._runtimes:
            try:
                alert = runtime.evaluate(SecurityEvent.from_dict(snapshot.to_dict()), self._watermark)
                if alert is not None:
                    alerts.append(alert)
            except Exception:
                logger.exception("Rule %s failed for event %s", runtime.rule.id, snapshot.event_id)
        return alerts

    def __call__(self, event):
        try:
            alerts = self.evaluate(event)
        except Exception:
            logger.exception("Rule engine failed; continuing event pipeline")
            return []
        for alert in alerts:
            for consumer in tuple(self._subscribers):
                try:
                    consumer(alert)
                except Exception:
                    logger.exception("Alert subscriber failed for rule %s", alert.rule_id)
        return alerts
