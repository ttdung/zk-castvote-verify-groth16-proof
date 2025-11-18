import hashlib
from typing import Optional, Dict
from risc0.risc0 import VerifierParameters, get_verifier_parameters as risc0_get_verifier_parameters
from .vk import vk_digest
from .utils import sha256, sha256_bytes


# selector -> verifier parameters
_risc0_selector_verifier_parameters: Dict[bytes, VerifierParameters] = {}


def _init_selector_parameters():
    """Initialize selector to verifier parameters mapping."""
    global _risc0_selector_verifier_parameters
    verifier_params = risc0_get_verifier_parameters()  # Call the risc0 function (no args)
    _risc0_selector_verifier_parameters = {}
    for params in verifier_params.values():
        selector = calculate_selector(params)
        _risc0_selector_verifier_parameters[selector] = params


def calculate_selector(params: VerifierParameters) -> bytes:
    """Calculate the selector from the verifier parameters."""
    data = bytearray(130)
    tag = sha256_bytes(b"risc0.Groth16ReceiptVerifierParameters")
    data[0:32] = tag
    data[32:64] = params.control_root
    data[64:96] = params.bn254_control_id
    data[96:128] = vk_digest
    data[128:130] = bytes([0x03, 0x00])
    h = sha256(bytes(data))
    return h[:4]


def get_verifier_parameters(selector: bytes) -> Optional[VerifierParameters]:
    """Get verifier parameters corresponding to the given selector."""
    if len(_risc0_selector_verifier_parameters) == 0:
        _init_selector_parameters()
    
    if len(selector) < 4:
        return None
    
    selector_4 = selector[:4]
    return _risc0_selector_verifier_parameters.get(selector_4)


def get_verifier_parameters2(selector: bytes) -> Optional[VerifierParameters]:
    """Get verifier parameters corresponding to the given selector (flexible length)."""
    return get_verifier_parameters(selector)

