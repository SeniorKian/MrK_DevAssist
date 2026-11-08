"""S3 flexible checksums: CRC32, CRC32C, CRC64NVME, SHA1, SHA256 (docs/30 §0, §8).

CRC32 uses ``zlib``. CRC32C and CRC64NVME use ``awscrt.checksums`` (Apache-2.0,
hardware accelerated, several GB/s). When awscrt is not importable a pure-Python
table implementation is used instead; it is correct but slow (~5-15 MB/s per core),
so production images pin awscrt.

Values are transported as base64 of the big-endian checksum bytes.
"""

from __future__ import annotations

import base64
import hashlib
import zlib
from collections.abc import Callable

try:  # pragma: no cover - exercised implicitly when awscrt is installed
    from awscrt import checksums as _crt
except Exception:  # pragma: no cover - fallback path tested directly
    _crt = None

ALGORITHMS = ("CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256")
HEADER_FOR = {name: f"x-amz-checksum-{name.lower()}" for name in ALGORITHMS}
ALGORITHM_FOR_HEADER = {header: name for name, header in HEADER_FOR.items()}
CRC_WIDTH = {"CRC32": 32, "CRC32C": 32, "CRC64NVME": 64}
_POLY = {"CRC32": 0xEDB88320, "CRC32C": 0x82F63B78, "CRC64NVME": 0x9A6C9329AC4BC9B5}

HAVE_AWSCRT = _crt is not None


def _table(poly: int) -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc)
    return table


_TABLES: dict[str, list[int]] = {}


def _py_crc(name: str) -> Callable[[bytes, int], int]:
    width = CRC_WIDTH[name]
    mask = (1 << width) - 1

    def update(data: bytes, previous: int = 0) -> int:
        table = _TABLES.get(name)
        if table is None:
            table = _TABLES[name] = _table(_POLY[name])
        crc = previous ^ mask
        for byte in memoryview(data).cast("B"):
            crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        return crc ^ mask

    return update


py_crc32c = _py_crc("CRC32C")
py_crc64nvme = _py_crc("CRC64NVME")

if _crt is not None:
    _crc32c: Callable[[bytes, int], int] = _crt.crc32c
    _crc64nvme: Callable[[bytes, int], int] = _crt.crc64nvme
else:  # pragma: no cover
    _crc32c = py_crc32c
    _crc64nvme = py_crc64nvme


class _Crc:
    __slots__ = ("_fn", "name", "value", "width")

    def __init__(self, name: str, fn: Callable[[bytes, int], int]) -> None:
        self.name = name
        self.width = CRC_WIDTH[name]
        self._fn = fn
        self.value = 0

    def update(self, data: bytes) -> None:
        self.value = self._fn(data, self.value)

    def digest(self) -> bytes:
        return self.value.to_bytes(self.width // 8, "big")


class _Hash:
    __slots__ = ("_hash", "name")

    def __init__(self, name: str) -> None:
        self.name = name
        self._hash = hashlib.sha1(usedforsecurity=False) if name == "SHA1" else hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._hash.update(data)

    def digest(self) -> bytes:
        return self._hash.digest()


def new_hasher(algorithm: str) -> _Crc | _Hash:
    if algorithm == "CRC32":
        return _Crc("CRC32", lambda data, prev: zlib.crc32(data, prev))
    if algorithm == "CRC32C":
        return _Crc("CRC32C", _crc32c)
    if algorithm == "CRC64NVME":
        return _Crc("CRC64NVME", _crc64nvme)
    if algorithm in {"SHA1", "SHA256"}:
        return _Hash(algorithm)
    raise ValueError(algorithm)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def compute(algorithm: str, data: bytes) -> str:
    hasher = new_hasher(algorithm)
    hasher.update(data)
    return b64(hasher.digest())


def normalize_algorithm(value: str | None) -> str | None:
    if not value:
        return None
    upper = value.strip().upper()
    return upper if upper in ALGORITHMS else None


def decode_value(algorithm: str, value: str) -> bytes | None:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (ValueError, TypeError):
        return None
    expected = {"CRC32": 4, "CRC32C": 4, "CRC64NVME": 8, "SHA1": 20, "SHA256": 32}[algorithm]
    return raw if len(raw) == expected else None


# --------------------------------------------------------------------------- combine


def _multmodp(a: int, b: int, poly: int, width: int) -> int:
    """Multiply a(x)*b(x) mod p(x) in the reflected representation (after zlib)."""
    m = 1 << (width - 1)
    p = 0
    while True:
        if a & m:
            p ^= b
            if (a & (m - 1)) == 0:
                break
        m >>= 1
        b = (b >> 1) ^ poly if b & 1 else b >> 1
    return p


_X2N: dict[str, list[int]] = {}


def _x2n_table(name: str) -> list[int]:
    table = _X2N.get(name)
    if table is None:
        width = CRC_WIDTH[name]
        poly = _POLY[name]
        p = 1 << (width - 2)  # x^1
        table = [p]
        for _ in range(1, 96):
            p = _multmodp(p, p, poly, width)
            table.append(p)
        _X2N[name] = table
    return table


def _x8nmodp(name: str, length: int) -> int:
    width = CRC_WIDTH[name]
    poly = _POLY[name]
    table = _x2n_table(name)
    p = 1 << (width - 1)  # x^0
    k = 3
    while length:
        if length & 1:
            p = _multmodp(table[k], p, poly, width)
        length >>= 1
        k += 1
    return p


def crc_combine(name: str, crc1: int, crc2: int, length2: int) -> int:
    """CRC of A||B from crc(A), crc(B) and len(B), for CRC32/CRC32C/CRC64NVME."""
    if length2 <= 0:
        return crc1
    return _multmodp(_x8nmodp(name, length2), crc1, _POLY[name], CRC_WIDTH[name]) ^ crc2


def combine_full_object(name: str, parts: list[tuple[bytes, int]]) -> bytes:
    """Full-object CRC from per-part CRC digests and sizes."""
    width = CRC_WIDTH[name]
    value = 0
    first = True
    for digest, size in parts:
        part = int.from_bytes(digest, "big")
        value = part if first else crc_combine(name, value, part, size)
        first = False
    return value.to_bytes(width // 8, "big")


def composite(name: str, part_digests: list[bytes]) -> str:
    hasher = new_hasher(name)
    for digest in part_digests:
        hasher.update(digest)
    return f"{b64(hasher.digest())}-{len(part_digests)}"
