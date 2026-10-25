"""M6 common model. Timestamps retain the sensor's monotonic nanoseconds."""

from dataclasses import asdict, dataclass, field, fields
from uuid import UUID, uuid4

if __package__:
    from .validation import validate_message
else:
    from validation import validate_message


@dataclass(frozen=True, kw_only=True)
class SecurityEvent:
    timestamp: int
    event_type: str
    event_category: str
    source: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None
    gid: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    tcp_flags: int | None = None
    interface: int | None = None
    syscall: str | None = None
    container_id: str | None = None
    cgroup_id: int | None = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        try:
            identifier = UUID(self.event_id)
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("invalid event_id") from error
        if identifier.version != 4 or str(identifier) != self.event_id:
            raise ValueError("event_id must be a canonical UUID4")
        if type(self.metadata) is not dict:
            raise ValueError("metadata must be an object")
        # M6 sensors do not supply container identity yet.
        if self.container_id is not None or self.cgroup_id is not None:
            raise ValueError("container identity unavailable from current sensors")
        network = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags", "interface")
        host = ("pid", "ppid", "uid", "gid", "process_name", "process_path", "syscall")
        if self.event_category == "network":
            if self.source != "xdp" or self.event_type != "network_packet":
                raise ValueError("invalid network source/type")
            if any(getattr(self, key) is not None for key in host):
                raise ValueError("host fields do not apply to network events")
            if set(self.metadata) != {"packet_length"}:
                raise ValueError("invalid network metadata")
            raw = {key: getattr(self, key) for key in network if key != "interface"}
            raw.update(timestamp=self.timestamp, ifindex=self.interface, **self.metadata)
        else:
            if self.source != "tracepoint" or any(getattr(self, key) is not None for key in network):
                raise ValueError("invalid host source/network fields")
            expected = set()
            if self.event_category in ("syscall", "privilege"):
                expected.add("syscall_return")
            if self.event_category == "privilege":
                expected.update(("previous_uid", "previous_gid"))
            if set(self.metadata) != expected:
                raise ValueError("invalid host metadata")
            raw = {key: getattr(self, key) for key in host}
            raw.update(timestamp=self.timestamp, event_type=self.event_type,
                       event_category=self.event_category, syscall_return=None,
                       previous_uid=None, previous_gid=None)
            raw.update(self.metadata)
        validate_message({"message_type": "event", "schema_version": 1, "event": raw})

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != {item.name for item in fields(cls)}:
            raise ValueError("invalid SecurityEvent fields")
        return cls(**value)


def normalize_message(message):
    """Validate an agent event envelope and produce one new SecurityEvent."""
    validate_message(message)
    if message["message_type"] != "event":
        raise ValueError("status messages are not telemetry")
    raw = message["event"]
    if "event_category" not in raw:
        values = {key: value for key, value in raw.items() if key not in {"ifindex", "packet_length"}}
        return SecurityEvent(**values, interface=raw["ifindex"], source="xdp",
                             event_type="network_packet", event_category="network",
                             metadata={"packet_length": raw["packet_length"]})
    extras = {key: raw[key] for key in ("syscall_return", "previous_uid", "previous_gid")
              if raw[key] is not None}
    values = {key: value for key, value in raw.items()
              if key not in {"syscall_return", "previous_uid", "previous_gid"}}
    return SecurityEvent(**values, source="tracepoint", metadata=extras)
