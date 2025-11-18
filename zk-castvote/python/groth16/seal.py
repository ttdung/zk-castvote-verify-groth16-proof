from typing import Tuple
from py_ecc.bn128 import FQ, FQ2
from py_ecc.bn128.bn128_curve import (
    b as b1,
    is_on_curve as g1_is_on_curve,
)


class ProofPairingData:
    """Proof pairing data structure."""
    def __init__(self, a: Tuple[FQ, FQ], b: Tuple[FQ2, FQ2], c: Tuple[FQ, FQ]):
        self.A = a
        self.B = b
        self.C = c


def decode_seal(seal: bytes) -> ProofPairingData:
    """Decode seal bytes into proof pairing data.
    
    The seal format matches Go's bn256.Unmarshal format:
    - A (G1): 64 bytes (32 bytes x, 32 bytes y)
    - B (G2): 128 bytes (32 bytes x1, 32 bytes x2, 32 bytes y1, 32 bytes y2)
    - C (G1): 64 bytes (32 bytes x, 32 bytes y)
    """
    if len(seal) != 256:
        raise ValueError(f"invalid seal length: {len(seal)}, expected 256")
    
    try:
        # Extract A (G1 point, 64 bytes)
        a_bytes = seal[0:64]
        a_x = FQ(int.from_bytes(a_bytes[0:32], 'big'))
        a_y = FQ(int.from_bytes(a_bytes[32:64], 'big'))
        a = (a_x, a_y)
        
        # Extract B (G2 point, 128 bytes)
        b_bytes = seal[64:192]
        # Go's bn256 marshaling stores the FQ2 coefficients in order (imaginary, real).
        # Reconstruct FQ2 elements accordingly: [real, imaginary].
        b_x_im = FQ(int.from_bytes(b_bytes[0:32], 'big'))
        b_x_re = FQ(int.from_bytes(b_bytes[32:64], 'big'))
        b_y_im = FQ(int.from_bytes(b_bytes[64:96], 'big'))
        b_y_re = FQ(int.from_bytes(b_bytes[96:128], 'big'))
        b = (FQ2([b_x_re, b_x_im]), FQ2([b_y_re, b_y_im]))
        
        # Extract C (G1 point, 64 bytes)
        c_bytes = seal[192:256]
        c_x = FQ(int.from_bytes(c_bytes[0:32], 'big'))
        c_y = FQ(int.from_bytes(c_bytes[32:64], 'big'))
        c = (c_x, c_y)
        
        # Validate points are on the curve
        if not g1_is_on_curve(a, b1):
            raise ValueError(f"A is not a valid G1 point: ({a_x}, {a_y})")
        if not g1_is_on_curve(c, b1):
            raise ValueError(f"C is not a valid G1 point: ({c_x}, {c_y})")
        
        # Note: G2 point validation happens during pairing operations
        return ProofPairingData(a, b, c)
    except Exception as e:
        raise ValueError(f"Failed to decode seal: {e}") from e

