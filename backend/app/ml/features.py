"""Feature extraction placeholders for future anomaly models."""


def extract_network_features(event: dict) -> list[float]:
    """Extract a minimal numeric feature vector for network events."""

    def event_type_num(value: object) -> float:
        mapping = {
            "net_conn_allowed": 1.0,
            "net_conn_high_risk": 2.0,
            "net_listener_open": 3.0,
        }
        return mapping.get(str(value or "").strip().lower(), 0.0)

    def process_hash(value: object) -> float:
        actor = str(value or "").lower()
        return float(sum(ord(ch) for ch in actor) % 1000)

    def parse_destination(resource: object, fallback_ip: object) -> tuple[str, float]:
        text = str(resource or "").strip()

        if "->" in text:
            destination = text.split("->", 1)[1].strip()
            if ":" in destination:
                ip_part, port_part = destination.rsplit(":", 1)
                try:
                    return ip_part.strip(), float(int(port_part))
                except ValueError:
                    return ip_part.strip(), 0.0
            return destination, 0.0

        ip_text = str(fallback_ip or "").strip()
        return ip_text, 0.0

    def is_external_ip(ip_value: str) -> float:
        if not ip_value:
            return 0.0
        lowered = ip_value.lower()
        if lowered.startswith("10.") or lowered.startswith("192.168."):
            return 0.0
        if lowered.startswith("172."):
            parts = lowered.split(".")
            if len(parts) > 1:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        return 0.0
                except ValueError:
                    pass
        return 1.0

    destination_ip, destination_port = parse_destination(
        event.get("resource"),
        event.get("ip"),
    )

    return [
        event_type_num(event.get("event_type")),
        process_hash(event.get("actor")),
        float(destination_port),
        is_external_ip(destination_ip),
    ]


def extract_cloud_features(event: dict) -> list[float]:
    """Return a minimal placeholder vector for cloud events."""
    return [0.0]


def extract_host_features(event: dict) -> list[float]:
    """Return a minimal placeholder vector for host events."""
    return [0.0]
