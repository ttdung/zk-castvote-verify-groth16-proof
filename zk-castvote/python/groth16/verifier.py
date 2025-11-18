import os
from typing import List
from py_ecc.bn128 import FQ, FQ2, FQ12, curve_order
from py_ecc.bn128.bn128_curve import (
    add as g1_add,
    multiply as g1_multiply,
    neg as g1_neg,
    Z1 as g1_zero,
)
from py_ecc.bn128.bn128_pairing import pairing

from risc0.risc0 import VerifierParameters
from .seal import decode_seal, ProofPairingData
from .vk import _vk
from .utils import split_digest, reverse_byte_order_uint256


# Field order
Q = curve_order


def verify_groth16(vk, proof: ProofPairingData, inputs: List[int]) -> None:
    """Verify Groth16 zkSNARK proof."""
    if len(inputs) + 1 != len(vk.IC):
        raise ValueError(f"len(inputs)+1 != len(vk.IC): {len(inputs)+1} != {len(vk.IC)}")
    
    try:
        # Start with zero point
        vk_x = g1_zero
        
        # Compute vkX = IC[0] + sum(IC[i+1] * inputs[i])
        for i in range(len(inputs)):
            # Check input is in field
            if inputs[i] >= Q:
                raise ValueError(f"input value {i} is not in the fields: {inputs[i]} >= {Q}")
            
            # vkX += IC[i+1] * inputs[i]
            ic_point = vk.IC[i + 1]
            scaled = g1_multiply(ic_point, inputs[i])
            vk_x = g1_add(vk_x, scaled)
        
        # Add IC[0]
        vk_x = g1_add(vk_x, vk.IC[0])
    except AssertionError as e:
        raise ValueError(f"Assertion error in vkX computation: {e}") from e
    except Exception as e:
        raise ValueError(f"Error computing vkX: {e}") from e
    
    try:
        # Negate vkX and Alpha
        vk_x_neg = g1_neg(vk_x)
        alpha_neg = g1_neg(vk.Alpha)
        c_neg = g1_neg(proof.C)
    except AssertionError as e:
        raise ValueError(f"Assertion error in point negation: {e}") from e
    except Exception as e:
        raise ValueError(f"Error negating points: {e}") from e
    
    # Prepare pairing inputs
    # G1: [A, -Alpha, -vkX, -C]
    g1_points = [proof.A, alpha_neg, vk_x_neg, c_neg]
    
    # G2: [B, Beta, Gamma, Delta]
    g2_points = [proof.B, vk.Beta, vk.Gamma, vk.Delta]
    
    # Validate that points are not None (point at infinity handling)
    for i, (g1_pt, g2_pt) in enumerate(zip(g1_points, g2_points)):
        if g1_pt is None:
            raise ValueError(f"G1 point {i} is None (point at infinity)")
        if g2_pt is None:
            raise ValueError(f"G2 point {i} is None (point at infinity)")
    
    try:
        # Perform pairing check: e(A, B) * e(-Alpha, Beta) * e(-vkX, Gamma) * e(-C, Delta) == 1
        # Note: py_ecc pairing takes (G2, G1) while Go's PairingCheck takes (G1, G2), so we reverse
        # Compute pairing product one at a time with better error reporting
        try:
            result = pairing(g2_points[0], g1_points[0])  # e(A, B)
        except AssertionError as e:
            raise ValueError(f"Assertion error in pairing e(A, B): {e}. This suggests the G2 point B from the seal may be invalid.") from e
        
        try:
            result = result * pairing(g2_points[1], g1_points[1])  # e(-Alpha, Beta)
        except AssertionError as e:
            raise ValueError(f"Assertion error in pairing e(-Alpha, Beta): {e}") from e
        
        try:
            result = result * pairing(g2_points[2], g1_points[2])  # e(-vkX, Gamma)
        except AssertionError as e:
            raise ValueError(f"Assertion error in pairing e(-vkX, Gamma): {e}") from e
        
        try:
            result = result * pairing(g2_points[3], g1_points[3])  # e(-C, Delta)
        except AssertionError as e:
            raise ValueError(f"Assertion error in pairing e(-C, Delta): {e}") from e
    except ValueError:
        # Re-raise our custom ValueError
        raise
    except AssertionError as e:
        raise ValueError(f"Assertion error in pairing computation: {e}. This may indicate invalid curve points.") from e
    except Exception as e:
        raise ValueError(f"Error in pairing computation: {e}") from e
    
    # Check if result is identity (1 in GT)
    # In py_ecc, the pairing returns an FQ12 element, we need to check if it equals the identity
    identity = FQ12.one()
    # Compare FQ12 elements properly
    # The pairing product should equal 1 (identity) for a valid proof
    if result != identity:
        # Provide more detailed error
        raise ValueError(f"invalid proofs: pairing result is not identity. Result: {result}")
    
    return None


def verify_integrity(params: VerifierParameters, seal: bytes, claim_digest: bytes) -> None:
    """Verify integrity of the seal against claim digest."""
    try:
        # Decode seal
        proof = decode_seal(seal)
    except Exception as e:
        raise ValueError(f"Failed to decode seal: {e}") from e
    
    try:
        # Split digests
        control0, control1 = split_digest(params.control_root)
        claim0, claim1 = split_digest(claim_digest)
    except Exception as e:
        raise ValueError(f"Failed to split digests: {e}") from e
    
    try:
        # Prepare public signals
        pub_signals = [
            int.from_bytes(control0, 'big'),
            int.from_bytes(control1, 'big'),
            int.from_bytes(claim0, 'big'),
            int.from_bytes(claim1, 'big'),
            int.from_bytes(reverse_byte_order_uint256(params.bn254_control_id), 'big'),
        ]
        if os.environ.get("GROTH16_DEBUG") == "1":
            print("Public signals (hex):")
            for idx, ps in enumerate(pub_signals):
                print(f"  s{idx}: {ps:032x}")
            print("Proof points:")
            print("  A:", proof.A[0].n, proof.A[1].n)
            print("  Bx:", proof.B[0].coeffs[0].n, proof.B[0].coeffs[1].n)
            print("  By:", proof.B[1].coeffs[0].n, proof.B[1].coeffs[1].n)
            print("  C:", proof.C[0].n, proof.C[1].n)
    except Exception as e:
        raise ValueError(f"Failed to prepare public signals: {e}") from e
    
    try:
        # Verify
        verify_groth16(_vk, proof, pub_signals)
    except AssertionError as e:
        raise ValueError(f"Assertion error in Groth16 verification: {e}. This may indicate invalid curve points or pairing computation failure.") from e
    except Exception as e:
        raise ValueError(f"Groth16 verification failed: {e}") from e

