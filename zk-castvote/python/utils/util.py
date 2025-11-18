import struct
import hashlib
from typing import Optional
from dataclasses import dataclass

from risc0.risc0 import calculate_claim_digest
from groth16.verifier import verify_integrity
from groth16.parameters import get_verifier_parameters2


@dataclass
class VoteResponse:
    nullifier: str
    age: int
    is_student: bool
    poll_id: int
    option_a: int
    option_b: int


@dataclass
class VoteRequest:
    seal: str
    journal: str
    journal_abi: str
    image_id: str
    nullifier: str
    age: int
    is_student: bool
    poll_id: int
    option_a: int
    option_b: int


def my_sha256(input_bytes: bytes) -> bytes:
    """Calculate SHA-256 hash."""
    return hashlib.sha256(input_bytes).digest()


def decode_bincode_vote(data: bytes) -> VoteResponse:
    """Decode bincode-encoded vote data."""
    offset = 0
    
    # Read string length (bincode uses u64 for length prefix, little-endian)
    str_len = struct.unpack('<Q', data[offset:offset+8])[0]
    offset += 8
    
    # Read string bytes
    str_bytes = data[offset:offset+str_len]
    offset += str_len
    nullifier = str_bytes.decode('utf-8')
    
    # Read age (u32, little-endian)
    age = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    
    # Read is_student (u8, little-endian)
    is_student_byte = struct.unpack('<B', data[offset:offset+1])[0]
    offset += 1
    is_student = is_student_byte != 0
    
    # Read poll_id (u64, little-endian)
    poll_id = struct.unpack('<Q', data[offset:offset+8])[0]
    offset += 8
    
    # Read option_a (u64, little-endian)
    option_a = struct.unpack('<Q', data[offset:offset+8])[0]
    offset += 8
    
    # Read option_b (u64, little-endian)
    option_b = struct.unpack('<Q', data[offset:offset+8])[0]
    
    return VoteResponse(
        nullifier=nullifier,
        age=age,
        is_student=is_student,
        poll_id=poll_id,
        option_a=option_a,
        option_b=option_b,
    )


def check_vote(vote: VoteRequest) -> VoteResponse:
    """Check and verify a vote."""
    # Decode image ID
    try:
        image_id_bytes = bytes.fromhex(vote.image_id)
        if len(image_id_bytes) != 32:
            raise ValueError(f"Invalid image_id length: {len(image_id_bytes)}")
        image_id = image_id_bytes
    except Exception as e:
        raise ValueError(f"Failed to decode imageID: {e}")
    
    # Decode journal
    try:
        journal_bytes = bytes.fromhex(vote.journal)
    except Exception as e:
        raise ValueError(f"Failed to decode journal: {e}")
    
    journal_digest = my_sha256(journal_bytes)
    claim_digest = calculate_claim_digest(image_id, journal_digest)
    
    print(f"claimDigest: {claim_digest.hex()}")
    
    # Decode seal
    try:
        seal_bytes = bytes.fromhex(vote.seal)
    except Exception as e:
        raise ValueError(f"Failed to decode seal: {e}")
    
    # Get verifier parameters from selector (first 4 bytes of seal)
    selector = seal_bytes[:4]
    params = get_verifier_parameters2(selector)
    if params is None:
        raise ValueError("GetVerifierParameters2 failed")
    
    # Verify integrity
    proof_seal = seal_bytes[4:]  # Skip selector
    try:
        verify_integrity(params, proof_seal, claim_digest)
        print("verify OK!")
    except Exception as e:
        import traceback
        error_msg = str(e) if str(e) else repr(e)
        print(f"Verification error: {error_msg}")
        print(traceback.format_exc())
        raise ValueError(f"Verification failed: {error_msg}")
    
    # Decode journal ABI
    try:
        data = bytes.fromhex(vote.journal_abi)
    except Exception as e:
        raise ValueError(f"Failed to decode hex string: {e}")
    
    vote_response = decode_bincode_vote(data)
    print(f"Decoded Vote: {vote_response}")
    print(f"Poll ID: {vote.poll_id}")
    
    return vote_response


def verify_encrypted_data_integrity(journal: str, ciphertext: str, aad: str) -> bool:
    """Verify encrypted data integrity."""
    # Extract cipherHashCode from journal (last 64 hex chars = 32 bytes)
    l = len(journal)
    cipher_hash_code_hex = journal[(l - 64):]
    
    try:
        decode_cipher_hash_code = bytes.fromhex(cipher_hash_code_hex)
    except Exception as e:
        print(e)
        return False
    
    try:
        ct = bytes.fromhex(ciphertext)
    except Exception:
        return False
    
    input_data = bytes(aad, 'utf-8') + ct
    cipher_hash = my_sha256(input_data)
    
    # Debug
    print(f"decodeCipherHashCode: {decode_cipher_hash_code.hex()}")
    print(f"cipherHash: {cipher_hash.hex()}")
    
    if decode_cipher_hash_code == cipher_hash:
        print("data1 is equal to data2")
        return True
    else:
        print("data1 is not equal to data2")
        return False

