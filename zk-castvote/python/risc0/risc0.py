import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, Optional

# System state zero digest constant
SYSTEM_STATE_ZERO_DIGEST = bytes.fromhex("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")


@dataclass
class VerifierParameters:
    control_root: bytes  # 32 bytes
    bn254_control_id: bytes  # 32 bytes


@dataclass
class ExitCode:
    system: int  # SystemExitCode
    user: int  # uint8


@dataclass
class Output:
    journal_digest: bytes  # 32 bytes
    assumptions_digest: bytes  # 32 bytes


@dataclass
class ReceiptClaim:
    pre_state_digest: bytes  # 32 bytes
    post_state_digest: bytes  # 32 bytes
    exit_code: ExitCode
    input: bytes  # 32 bytes
    output: bytes  # 32 bytes


# System exit codes
HALTED = 0
PAUSED = 1
SYSTEM_SPLIT = 2


def sha256(input_bytes: bytes) -> bytes:
    """Calculate SHA-256 hash."""
    return hashlib.sha256(input_bytes).digest()


def sha256_bytes(input_bytes: bytes) -> bytes:
    """Calculate SHA-256 hash and return as bytes."""
    return sha256(input_bytes)


def output_digest(output: Output) -> bytes:
    """Calculate digest of Output struct."""
    data = bytearray(98)
    tag = sha256_bytes(b"risc0.Output")
    data[0:32] = tag
    data[32:64] = output.journal_digest
    data[64:96] = output.assumptions_digest
    data[96:98] = bytes([0x02, 0x00])
    return sha256(bytes(data))


def receipt_claim_digest(rc: ReceiptClaim) -> bytes:
    """Calculate digest of ReceiptClaim."""
    data = bytearray(170)
    tag = sha256_bytes(b"risc0.ReceiptClaim")
    data[0:32] = tag
    data[32:64] = rc.input
    data[64:96] = rc.pre_state_digest
    data[96:128] = rc.post_state_digest
    data[128:160] = rc.output
    # Exit code encoding
    data[160:164] = struct.pack('>I', (rc.exit_code.system << 24))
    data[164:168] = struct.pack('>I', (rc.exit_code.user << 24))
    data[168:170] = bytes([0x04, 0x00])
    return sha256(bytes(data))


def get_ok_receipt_claim(system_state_zero_digest: bytes, image_id: bytes, journal_digest: bytes) -> ReceiptClaim:
    """Create an OK receipt claim."""
    output = Output(
        journal_digest=journal_digest,
        assumptions_digest=bytes(32),  # Empty
    )
    output_digest_bytes = output_digest(output)
    
    return ReceiptClaim(
        pre_state_digest=image_id,
        post_state_digest=system_state_zero_digest,
        exit_code=ExitCode(system=HALTED, user=0),
        input=bytes(32),  # Empty
        output=output_digest_bytes,
    )


def calculate_claim_digest(image_id: bytes, journal_digest: bytes) -> bytes:
    """Calculate claim digest from image ID and journal digest."""
    claim = get_ok_receipt_claim(SYSTEM_STATE_ZERO_DIGEST, image_id, journal_digest)
    return receipt_claim_digest(claim)


def build_verifier_parameters(control_root: str, bn254_control_id: str) -> VerifierParameters:
    """Build verifier parameters from hex strings."""
    control_root_bytes = bytes.fromhex(control_root)
    bn254_control_id_bytes = bytes.fromhex(bn254_control_id)
    
    if len(control_root_bytes) != 32 or len(bn254_control_id_bytes) != 32:
        raise ValueError("Invalid parameter length")
    
    return VerifierParameters(
        control_root=control_root_bytes,
        bn254_control_id=bn254_control_id_bytes,
    )



def get_verifier_parameters() -> Dict[str, VerifierParameters]:
    """Get all RISC0 verifier parameters by version."""
    return {
        "1.0": build_verifier_parameters(
            "a516a057c9fbf5629106300934d48e0e775d4230e41e503347cad96fcbde7e2e",
            "51b54a62f2aa599aef768744c95de8c7d89bf716e11b1179f05d6cf0bcfeb60e",
        ),
        "1.1": build_verifier_parameters(
            "8b6dcf11d463ac455361b41fb3ed053febb817491bdea00fdb340e45013b852e",
            "4e160df1e119ac0e3d658755a9edf38c8feb307b34bc10b57f4538dbe122a005",
        ),
        "1.2": build_verifier_parameters(
            "8cdad9242664be3112aba377c5425a4df735eb1c6966472b561d2855932c0469",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "1.3": build_verifier_parameters(
            "6fcbfc564e08874a235c181e75bb53547402b116957f700497bf482e08060a15",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "2.0": build_verifier_parameters(
            "539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "2.1": build_verifier_parameters(
            "884389273e128b32475b334dec75ee619b77cb33d41c332021fe7e44c746ee60",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "2.2": build_verifier_parameters(
            "ce52bf56033842021af3cf6db8a50d1b7535c125a34f1a22c6fdcf002c5a1529",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "2.3": build_verifier_parameters(
            "ce52bf56033842021af3cf6db8a50d1b7535c125a34f1a22c6fdcf002c5a1529",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
        "3.0": build_verifier_parameters(
            "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56",
            "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
        ),
    }


def find_verifier_parameters(version: str) -> Optional[VerifierParameters]:
    """Find verifier parameters by version."""
    params = get_verifier_parameters()
    return params.get(version)

