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


class _Session:
    """Bounded evidence plus exact aggregate counts for one IP pair.

    Pending confirmation retains fewer than threshold window samples. Once
    confirmed, those samples are discarded; only aggregates, an 8192-byte scan
    port bitmap, and capped UUID samples/recent replay checks remain.
    """

    def __init__(self, scan):
        self.pending = {}
        self.ports = bytearray(8192) if scan else None
        self.unique_port_count = 0
        self.matching_event_count = 0
        self.first_timestamp = None
        self.last_timestamp = None
        self.first_event_id = None
        self.last_event_id = None
        self.threshold_timestamp = None
        self.evidence = {}  # First max_event_ids - 2 UUIDs; reserve endpoints.
        self.recent_ids = OrderedDict()

    @property
    def active(self):
        return self.threshold_timestamp is not None

    def observe(self, event, rule):
        # Bounded replay protection, not an unbounded lifetime UUID index.
        if (event.event_id in self.recent_ids or event.event_id in self.evidence
                or event.event_id in (self.first_event_id, self.last_event_id)
                or (not self.active and event.event_id in self.pending)):
            return False
        self.recent_ids[event.event_id] = None
        if len(self.recent_ids) > rule.max_event_ids:
            self.recent_ids.popitem(last=False)
        if len(self.evidence) < rule.max_event_ids - 2:
            self.evidence[event.event_id] = None
        self.matching_event_count += 1
        if self.first_timestamp is None or event.timestamp < self.first_timestamp:
            self.first_timestamp, self.first_event_id = event.timestamp, event.event_id
        if self.last_timestamp is None or event.timestamp >= self.last_timestamp:
            self.last_timestamp, self.last_event_id = event.timestamp, event.event_id
        if self.ports is not None:
            index, bit = divmod(event.dst_port, 8)
            mask = 1 << bit
            if not self.ports[index] & mask:
                self.ports[index] |= mask
                self.unique_port_count += 1
        if not self.active:
            sample_key = event.dst_port if self.ports is not None else event.event_id
            previous = self.pending.get(sample_key)
            if previous is None or event.timestamp >= previous:
                self.pending[sample_key] = event.timestamp
        return True

    def event_ids(self):
        return tuple(dict.fromkeys((*self.evidence, self.first_event_id, self.last_event_id)))


class _Runtime:
    def __init__(self, rule):
        self.rule = rule
        self.groups = OrderedDict()
        self.closed_before = OrderedDict()

    def _alert(self, timestamp, event_ids, metadata):
        rule = self.rule
        return Alert(timestamp=timestamp, rule_id=rule.id, rule_name=rule.name,
                     alert_type=rule.type, severity=rule.severity, description=rule.description,
                     source_event_ids=tuple(event_ids), event_category=rule.category,
                     metadata=metadata)

    def _finish(self, key, timestamp, reason):
        session = self.groups.pop(key)  # Release state even if alert construction fails.
        self.closed_before[key] = timestamp
        self.closed_before.move_to_end(key)
        if len(self.closed_before) > self.rule.max_groups:
            self.closed_before.popitem(last=False)
        rule = self.rule
        event_ids = session.event_ids()
        metadata = {
            "src_ip": key[0], "dst_ip": key[1], "threshold": rule.threshold,
            "window_ns": rule.window_ns, "quiet_ns": rule.quiet_ns,
            "max_detection_ns": rule.max_detection_ns,
            "matching_event_count": session.matching_event_count,
            "first_timestamp": session.first_timestamp,
            "threshold_timestamp": session.threshold_timestamp,
            "last_timestamp": session.last_timestamp,
            "duration_ns": session.last_timestamp - session.first_timestamp,
            "first_event_id": session.first_event_id, "last_event_id": session.last_event_id,
            "source_event_ids_truncated": session.matching_event_count > len(event_ids),
            "finalization_reason": reason,
        }
        if session.ports is not None:
            metadata["unique_port_count"] = session.unique_port_count
            metadata["destination_ports"] = [
                port for port in range(1, 65536)
                if session.ports[port // 8] & (1 << (port % 8))]
        return self._alert(timestamp, event_ids, metadata)

    def advance(self, watermark):
        for key, timestamp in list(self.closed_before.items()):
            if timestamp <= watermark - self.rule.window_ns:
                del self.closed_before[key]
        alerts = []
        for key, session in list(self.groups.items()):
            if session.active:
                # A delayed event can confirm an already quiet historical run.
                # Its alert must never predate the observed confirmation.
                quiet_end = max(session.last_timestamp + self.rule.quiet_ns,
                                session.threshold_timestamp)
                maximum_end = session.threshold_timestamp + self.rule.max_detection_ns
                deadline = min(quiet_end, maximum_end)
                if watermark >= deadline:
                    reason = "quiet" if quiet_end <= maximum_end else "max_duration"
                    alerts.append(self._finish(key, deadline, reason))
            else:
                cutoff = watermark - self.rule.window_ns
                for sample_key, timestamp in list(session.pending.items()):
                    if timestamp <= cutoff:
                        del session.pending[sample_key]
                if not session.pending:
                    del self.groups[key]
        return alerts

    def flush(self, watermark, reason):
        alerts = []
        for key, session in list(self.groups.items()):
            if session.active:
                alerts.append(self._finish(key, watermark, reason))
            else:
                del self.groups[key]
        return alerts

    def evaluate(self, event, watermark):
        rule = self.rule
        alerts = self.advance(watermark)
        if rule.category != "network":
            alert = self._host(event)
            return alerts + ([alert] if alert is not None else [])
        if event.event_category != "network":
            return alerts
        if event.protocol == "OTHER" or event.src_ip == "0.0.0.0" or event.dst_ip == "0.0.0.0":
            return alerts
        if rule.type in ("port_scan", "syn_flood"):
            if event.protocol != "TCP" or event.tcp_flags & 0x12 != 0x02 or not event.dst_port:
                return alerts
        key = (event.src_ip, event.dst_ip)
        session = self.groups.get(key)
        if event.timestamp < self.closed_before.get(key, 0):
            return alerts
        # Pending samples must be in the confirmation window. Active sessions
        # may include late activity from their observed lifetime, even if it is
        # outside that window; no old input may create/reopen a closed session.
        if session is not None and session.active:
            if (event.timestamp < session.first_timestamp
                    and event.timestamp <= watermark - rule.window_ns):
                return alerts
        elif event.timestamp <= watermark - rule.window_ns:
            return alerts
        if session is None:
            if len(self.groups) >= rule.max_groups:
                # Never discard a confirmed session or force an early alert for
                # capacity. Prefer evicting the oldest unconfirmed candidate.
                victim = next((key for key, value in self.groups.items() if not value.active), None)
                if victim is None:
                    return alerts
                del self.groups[victim]
            session = _Session(rule.type == "port_scan")
            self.groups[key] = session
        self.groups.move_to_end(key)
        if session.observe(event, rule) and not session.active and len(session.pending) >= rule.threshold:
            session.threshold_timestamp = watermark
            session.pending.clear()
            # A late packet can confirm activity that is already quiet.
            alerts.extend(self.advance(watermark))
        return alerts

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
    Event-time windows/sessions use a nondecreasing high watermark. advance_time
    returns timer alerts; tick publishes them. flush publishes remaining active
    sessions on stream termination. No background thread or wall-clock dependency.
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
                alerts.extend(runtime.evaluate(SecurityEvent.from_dict(snapshot.to_dict()), self._watermark))
            except Exception:
                logger.exception("Rule %s failed for event %s", runtime.rule.id, snapshot.event_id)
        return alerts

    def advance_time(self, timestamp):
        """Advance sensor monotonic time without an event; return finalized alerts."""
        if type(timestamp) is not int or not 0 <= timestamp < (1 << 64):
            raise ValueError("invalid rule clock timestamp")
        self._watermark = max(self._watermark, timestamp)
        alerts = []
        for runtime in self._runtimes:
            try:
                alerts.extend(runtime.advance(self._watermark))
            except Exception:
                logger.exception("Rule %s timer failed", runtime.rule.id)
        return alerts

    def _publish(self, alerts):
        for alert in alerts:
            for consumer in tuple(self._subscribers):
                try:
                    consumer(alert)
                except Exception:
                    logger.exception("Alert subscriber failed for rule %s", alert.rule_id)
        return alerts

    def tick(self, timestamp):
        """Failure-contained timer subscriber; also publishes finalized alerts."""
        try:
            return self._publish(self.advance_time(timestamp))
        except Exception:
            logger.exception("Rule engine timer failed; continuing event pipeline")
            return []

    def flush(self, reason="stream_end"):
        """Publish confirmed sessions once; discard unconfirmed candidates."""
        if reason not in ("stream_end", "shutdown"):
            raise ValueError("invalid rule flush reason")
        alerts = []
        for runtime in self._runtimes:
            try:
                alerts.extend(runtime.flush(self._watermark, reason))
            except Exception:
                logger.exception("Rule %s flush failed", runtime.rule.id)
        return self._publish(alerts)

    def __call__(self, event):
        try:
            return self._publish(self.evaluate(event))
        except Exception:
            logger.exception("Rule engine failed; continuing event pipeline")
            return []
