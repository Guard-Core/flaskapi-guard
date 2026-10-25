CLIENT_IP = "203.0.113.5"

_TYPE_STRING = 2
_TYPE_UINT16 = 5
_TYPE_UINT32 = 6
_TYPE_MAP = 7
_TYPE_UINT64 = 9
_TYPE_ARRAY = 11
_NODE = "node"
_DATA = "data"


def _mmdb_control_byte(data_type: int, size: int) -> bytes:
    if data_type <= 7:
        return bytes([(data_type << 5) | size])
    return bytes([size, data_type - 7])


def _mmdb_encode_string(value: str) -> bytes:
    payload = value.encode("utf-8")
    return _mmdb_control_byte(_TYPE_STRING, len(payload)) + payload


def _mmdb_encode_uint(data_type: int, value: int, byte_len: int) -> bytes:
    raw = value.to_bytes(byte_len, "big").lstrip(b"\x00")
    return _mmdb_control_byte(data_type, len(raw)) + raw


def _mmdb_country_record(country: str) -> bytes:
    key = _mmdb_encode_string("country")
    value = _mmdb_encode_string(country)
    return _mmdb_control_byte(_TYPE_MAP, 1) + key + value


def _mmdb_metadata(node_count: int) -> bytes:
    entries: dict[str, bytes] = {
        "node_count": _mmdb_encode_uint(_TYPE_UINT32, node_count, 4),
        "record_size": _mmdb_encode_uint(_TYPE_UINT16, 24, 2),
        "ip_version": _mmdb_encode_uint(_TYPE_UINT16, 4, 2),
        "database_type": _mmdb_encode_string("guard-core-live-smoke"),
        "languages": _mmdb_control_byte(_TYPE_ARRAY, 1) + _mmdb_encode_string("en"),
        "binary_format_major_version": _mmdb_encode_uint(_TYPE_UINT16, 2, 2),
        "binary_format_minor_version": _mmdb_encode_uint(_TYPE_UINT16, 0, 2),
        "build_epoch": _mmdb_encode_uint(_TYPE_UINT64, 1_700_000_000, 8),
        "description": (
            _mmdb_control_byte(_TYPE_MAP, 1)
            + _mmdb_encode_string("en")
            + _mmdb_encode_string("guard-core-live-smoke")
        ),
    }
    body = _mmdb_control_byte(_TYPE_MAP, len(entries))
    for key, encoded_value in entries.items():
        body += _mmdb_encode_string(key) + encoded_value
    return body


def _build_single_entry_mmdb(ip: str, country: str) -> bytes:
    octets = [int(part) for part in ip.split(".")]
    bits = "".join(f"{octet:08b}" for octet in octets)

    nodes: list[list[tuple[str, int] | None]] = [[None, None]]
    node_idx = 0
    for position, bit in enumerate(bits):
        branch = int(bit)
        if position == len(bits) - 1:
            nodes[node_idx][branch] = (_DATA, 0)
        else:
            nodes.append([None, None])
            child_idx = len(nodes) - 1
            nodes[node_idx][branch] = (_NODE, child_idx)
            node_idx = child_idx

    node_count = len(nodes)
    data_section = _mmdb_country_record(country)

    def resolve(value: tuple[str, int] | None) -> int:
        if value is None:
            return node_count
        kind, payload = value
        if kind == _NODE:
            return payload
        return node_count + 16

    tree = bytearray()
    for left, right in nodes:
        tree += resolve(left).to_bytes(3, "big")
        tree += resolve(right).to_bytes(3, "big")

    return (
        bytes(tree)
        + b"\x00" * 16
        + data_section
        + b"\xab\xcd\xefMaxMind.com"
        + _mmdb_metadata(node_count)
    )


def country_database_bytes(country: str, ip: str = CLIENT_IP) -> bytes:
    return _build_single_entry_mmdb(ip, country)
