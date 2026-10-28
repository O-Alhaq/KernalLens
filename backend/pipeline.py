"""Synchronous normalized event stream and subscriber routing for future consumers."""

if __package__:
    from .events import SecurityEvent, normalize_message
else:
    from events import SecurityEvent, normalize_message


def receive_events(connection, on_status=None, on_idle=None):
    # Lazy import keeps the wire decoder independently usable for M3 regressions.
    if __package__:
        from .receiver import receive_messages
    else:
        from receiver import receive_messages
    for message in receive_messages(connection, on_idle=on_idle):
        if message["message_type"] == "status":
            if on_status is not None:
                on_status(message)
        else:
            yield normalize_message(message)


class EventRouter:
    """Deliver only validated SecurityEvents; subscriber failures propagate."""

    def __init__(self):
        self._subscribers = []

    def subscribe(self, consumer, *, category=None):
        if not callable(consumer):
            raise ValueError("consumer must be callable")
        if category is not None and category not in ("network", "process", "syscall", "privilege"):
            raise ValueError("unsupported routing category")
        self._subscribers.append((category, consumer))

    def route(self, event):
        if not isinstance(event, SecurityEvent):
            raise ValueError("router requires a SecurityEvent")
        # Revalidate because metadata is a mutable dictionary.
        SecurityEvent.from_dict(event.to_dict())
        for category, consumer in tuple(self._subscribers):
            if category is None or category == event.event_category:
                consumer(event)
