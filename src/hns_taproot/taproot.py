"""
Taproot output construction: tweak an internal x-only public key with a
MAST merkle root to derive the single output key that gets published
on-chain. Spending can then take either path:

  * key path  -- a single Schnorr signature from the (tweaked) output key,
                 used for the cooperative/common case (e.g. a routine
                 TRANSFER+FINALIZE by the name owner).
  * script path -- reveal one leaf script + its control block (merkle
                 proof), used for conditional spends (e.g. a recovery
                 script, a multisig registrar policy, a timelocked
                 fallback claim).

This mirrors BIP341's tweak construction (t = tagged_hash("TapTweak", P || root);
Q = P + t*G) using the pure-Python curve ops in secp256k1.py.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import secp256k1 as C
from .mast import TapTree
from .schnorr import tagged_hash, pubkey_from_privkey


@dataclass
class TaprootOutput:
    internal_pubkey: bytes  # 32-byte x-only
    output_pubkey: bytes  # 32-byte x-only, this is what goes in the scriptPubKey
    output_parity_even: bool
    tweak: int
    merkle_root: bytes | None


def tweak_pubkey(internal_pubkey_x: bytes, merkle_root: bytes | None) -> TaprootOutput:
    P = C.point_from_x(C.int_from_bytes(internal_pubkey_x), want_even_y=True)
    t_data = internal_pubkey_x + (merkle_root or b"")
    t = C.int_from_bytes(tagged_hash("TapTweak", t_data)) % C.N
    if t == 0 or t >= C.N:
        raise ValueError("invalid tweak")
    Q = C.point_add(P, C.point_mul(C.G, t))
    if Q is None:
        raise ValueError("tweak produced point at infinity")
    return TaprootOutput(
        internal_pubkey=internal_pubkey_x,
        output_pubkey=C.bytes_from_point(Q),
        output_parity_even=C.has_even_y(Q),
        tweak=t,
        merkle_root=merkle_root,
    )


def tweak_privkey(internal_privkey: bytes, merkle_root: bytes | None) -> bytes:
    """Derive the private key corresponding to the tweaked output key,
    for key-path spending. Handles the even-y negation BIP340/341 require."""
    d0 = C.int_from_bytes(internal_privkey)
    P = C.point_mul(C.G, d0)
    if not C.has_even_y(P):
        d0 = C.N - d0
    internal_pub_x = C.bytes_from_point(C.point_mul(C.G, d0))
    t = C.int_from_bytes(tagged_hash("TapTweak", internal_pub_x + (merkle_root or b""))) % C.N
    d = (d0 + t) % C.N
    return C.bytes_from_int(d)


def output_from_internal_privkey(internal_privkey: bytes, tree: TapTree | None = None) -> TaprootOutput:
    internal_pub = pubkey_from_privkey(internal_privkey)
    root = tree.merkle_root() if tree is not None else None
    return tweak_pubkey(internal_pub, root)


def build_control_block(
    internal_pubkey_x: bytes,
    tree: TapTree,
    leaf_index: int,
    output_parity_even: bool,
) -> bytes:
    """Control block = version_byte || internal_pubkey || path_of_sibling_hashes."""
    leaf = tree.leaves[leaf_index]
    parity_bit = 0 if output_parity_even else 1
    version_byte = (leaf.leaf_version & 0xFE) | parity_bit
    path = tree.control_path(leaf_index)
    return bytes([version_byte]) + internal_pubkey_x + b"".join(path)
