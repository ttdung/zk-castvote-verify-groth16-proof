import hashlib
import struct
from typing import List


def sha256(input_bytes: bytes) -> bytes:
    """Calculate SHA-256 hash."""
    return hashlib.sha256(input_bytes).digest()


def sha256_bytes(input_bytes: bytes) -> bytes:
    """Calculate SHA-256 hash and return as bytes."""
    return sha256(input_bytes)


def sha256_items(*items: bytes) -> bytes:
    """Hash multiple 32-byte items."""
    data = b''.join(items)
    return sha256_bytes(data)


def reverse_byte_order_uint256(input_bytes: bytes) -> bytes:
    """Reverse byte order of a 32-byte value."""
    return bytes(reversed(input_bytes))


def split_digest(digest: bytes) -> tuple[bytes, bytes]:
    """Split a 32-byte digest into two 16-byte parts (upper and lower), matching Go's ordering."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    reversed_digest = reverse_byte_order_uint256(digest)
    lower128 = reversed_digest[:16]
    upper128 = reversed_digest[16:32]
    return upper128, lower128


def tagged_struct(tag_digest: bytes, down: List[bytes]) -> bytes:
    """Create a tagged struct hash."""
    down_len = len(down)
    # Swap bytes for little-endian representation
    down_len_le = struct.pack('<H', down_len)
    down_packed = b''.join(down)
    data = tag_digest + down_packed + down_len_le
    return sha256(data)


def tagged_list_cons(tag_digest: bytes, head: bytes, tail: bytes) -> bytes:
    """Create a tagged list cons hash."""
    return tagged_struct(tag_digest, [head, tail])


def tagged_list(tag_digest: bytes, items: List[bytes]) -> bytes:
    """Create a tagged list hash."""
    curr = bytes(32)
    for i in range(len(items) - 1, -1, -1):
        curr = tagged_list_cons(tag_digest, items[i], curr)
    return curr


def concat_bytes32(*bzs: bytes) -> bytes:
    """Concatenate multiple 32-byte values."""
    return b''.join(bzs)

