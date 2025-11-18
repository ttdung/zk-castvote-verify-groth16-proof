from typing import List, Tuple
from py_ecc.bn128 import FQ, FQ2
from .utils import sha256, sha256_bytes, sha256_items, tagged_list, concat_bytes32


def parse_big_int(s: str) -> bytes:
    """Parse a big integer string and return as 32-byte array."""
    bi = int(s)
    return bi.to_bytes(32, 'big')


def fq_from_bytes(chunk: bytes) -> FQ:
    return FQ(int.from_bytes(chunk, 'big'))


def fq2_from_go_chunks(chunk_im: bytes, chunk_re: bytes) -> FQ2:
    """Go bn256 encodes FQ2 as [imaginary || real]. Convert to py_ecc format."""
    return FQ2([fq_from_bytes(chunk_re), fq_from_bytes(chunk_im)])


# Verification key constants
def get_alphas() -> List[bytes]:
    return [
        parse_big_int("20491192805390485299153009773594534940189261866228447918068658471970481763042"),
        parse_big_int("9383485363053290200918347156157836566562967994039712273449902621266178545958"),
    ]


def get_betas() -> List[bytes]:
    return [
        parse_big_int("4252822878758300859123897981450591353533073413197771768651442665752259397132"),
        parse_big_int("6375614351688725206403948262868962793625744043794305715222011528459656738731"),
        parse_big_int("21847035105528745403288232691147584728191162732299865338377159692350059136679"),
        parse_big_int("10505242626370262277552901082094356697409835680220590971873171140371331206856"),
    ]


def get_gammas() -> List[bytes]:
    return [
        parse_big_int("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
        parse_big_int("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
        parse_big_int("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
        parse_big_int("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
    ]


def get_deltas() -> List[bytes]:
    return [
        parse_big_int("1668323501672964604911431804142266013250380587483576094566949227275849579036"),
        parse_big_int("12043754404802191763554326994664886008979042643626290185762540825416902247219"),
        parse_big_int("7710631539206257456743780535472368339139328733484942210876916214502466455394"),
        parse_big_int("13740680757317479711909903993315946540841369848973133181051452051592786724563"),
    ]


def get_ics() -> List[List[bytes]]:
    return [
        [
            parse_big_int("8446592859352799428420270221449902464741693648963397251242447530457567083492"),
            parse_big_int("1064796367193003797175961162477173481551615790032213185848276823815288302804"),
        ],
        [
            parse_big_int("3179835575189816632597428042194253779818690147323192973511715175294048485951"),
            parse_big_int("20895841676865356752879376687052266198216014795822152491318012491767775979074"),
        ],
        [
            parse_big_int("5332723250224941161709478398807683311971555792614491788690328996478511465287"),
            parse_big_int("21199491073419440416471372042641226693637837098357067793586556692319371762571"),
        ],
        [
            parse_big_int("12457994489566736295787256452575216703923664299075106359829199968023158780583"),
            parse_big_int("19706766271952591897761291684837117091856807401404423804318744964752784280790"),
        ],
        [
            parse_big_int("19617808913178163826953378459323299110911217259216006187355745713323154132237"),
            parse_big_int("21663537384585072695701846972542344484111393047775983928357046779215877070466"),
        ],
        [
            parse_big_int("6834578911681792552110317589222010969491336870276623105249474534788043166867"),
            parse_big_int("15060583660288623605191393599883223885678013570733629274538391874953353488393"),
        ],
    ]


class VK:
    """Verification Key data structure."""
    def __init__(self):
        alphas = get_alphas()
        betas = get_betas()
        gammas = get_gammas()
        deltas = get_deltas()
        ics = get_ics()
        
        # Alpha (G1 point)
        alpha_bytes = concat_bytes32(alphas[0], alphas[1])
        self.Alpha = (
            fq_from_bytes(alpha_bytes[0:32]),
            fq_from_bytes(alpha_bytes[32:64]),
        )
        
        # Beta (G2 point)
        beta_bytes = concat_bytes32(betas[0], betas[1], betas[2], betas[3])
        self.Beta = (
            fq2_from_go_chunks(beta_bytes[0:32], beta_bytes[32:64]),
            fq2_from_go_chunks(beta_bytes[64:96], beta_bytes[96:128]),
        )
        
        # Gamma (G2 point)
        gamma_bytes = concat_bytes32(gammas[0], gammas[1], gammas[2], gammas[3])
        self.Gamma = (
            fq2_from_go_chunks(gamma_bytes[0:32], gamma_bytes[32:64]),
            fq2_from_go_chunks(gamma_bytes[64:96], gamma_bytes[96:128]),
        )
        
        # Delta (G2 point)
        delta_bytes = concat_bytes32(deltas[0], deltas[1], deltas[2], deltas[3])
        self.Delta = (
            fq2_from_go_chunks(delta_bytes[0:32], delta_bytes[32:64]),
            fq2_from_go_chunks(delta_bytes[64:96], delta_bytes[96:128]),
        )
        
        # IC (G1 points)
        self.IC = []
        for ic in ics:
            ic_bytes = concat_bytes32(ic[0], ic[1])
            ic_point = (
                fq_from_bytes(ic_bytes[0:32]),
                fq_from_bytes(ic_bytes[32:64]),
            )
            self.IC.append(ic_point)


def verifier_key_digest() -> bytes:
    """Calculate verification key digest."""
    ics = get_ics()
    ic_digests = []
    for ic in ics:
        ic_digest = sha256(concat_bytes32(ic[0], ic[1]))
        ic_digests.append(ic_digest)
    
    alphas = get_alphas()
    betas = get_betas()
    gammas = get_gammas()
    deltas = get_deltas()
    
    data = bytearray()
    data.extend(sha256_bytes(b"risc0_groth16.VerifyingKey"))
    data.extend(sha256_items(alphas[0], alphas[1]))
    data.extend(sha256_items(betas[0], betas[1], betas[2], betas[3]))
    data.extend(sha256_items(gammas[0], gammas[1], gammas[2], gammas[3]))
    data.extend(sha256_items(deltas[0], deltas[1], deltas[2], deltas[3]))
    data.extend(tagged_list(sha256(b"risc0_groth16.VerifyingKey.IC"), ic_digests))
    data.extend(bytes([0x05, 0x00]))
    return sha256(bytes(data))


# Initialize verification key and digest
_vk = VK()
vk_digest = verifier_key_digest()

