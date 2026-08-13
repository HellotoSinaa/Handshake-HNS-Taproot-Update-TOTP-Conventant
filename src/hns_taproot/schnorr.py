"""
BIP340-style Schnorr signatures over secp256k1.

Implements tagged hashing, key generation, x-only public keys, signing,
and verification, following the structure of BIP340. Used as the
signature scheme for both the internal (key-path) and script-path
spends in the Taproot module.
"""
from __future__ import annotations

import hashlib
import secrets

from . import secp256k1 as C


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def generate_privkey() -> bytes:
    return secrets.token_bytes(32)


def pubkey_from_privkey(privkey: bytes) -> bytes:
    """Return the 32-byte x-only public key for a given private key."""
    d0 = C.int_from_bytes(privkey)
    if not (1 <= d0 < C.N):
        raise ValueError("private key out of range")
    P = C.point_mul(C.G, d0)
    return C.bytes_from_point(P)


def _even_y_privkey(privkey_int: int) -> int:
    P = C.point_mul(C.G, privkey_int)
    if not C.has_even_y(P):
        privkey_int = C.N - privkey_int
    return privkey_int


def sign(msg_hash: bytes, privkey: bytes, aux_rand: bytes | None = None) -> bytes:
    if len(msg_hash) != 32:
        raise ValueError("msg_hash must be 32 bytes")
    d0 = C.int_from_bytes(privkey)
    if not (1 <= d0 < C.N):
        raise ValueError("private key out of range")
    if aux_rand is None:
        aux_rand = secrets.token_bytes(32)

    d = _even_y_privkey(d0)
    t = (d ^ C.int_from_bytes(tagged_hash("BIP0340/aux", aux_rand))).to_bytes(32, "big")
    Px = C.bytes_from_point(C.point_mul(C.G, d))
    k0 = C.int_from_bytes(tagged_hash("BIP0340/nonce", t + Px + msg_hash)) % C.N
    if k0 == 0:
        raise ValueError("nonce derivation produced 0 (astronomically unlikely)")

    R = C.point_mul(C.G, k0)
    k = C.N - k0 if not C.has_even_y(R) else k0
    Rx = C.bytes_from_point(R)
    e = C.int_from_bytes(tagged_hash("BIP0340/challenge", Rx + Px + msg_hash)) % C.N
    s = (k + e * d) % C.N
    return Rx + C.bytes_from_int(s)


def verify(msg_hash: bytes, pubkey_x: bytes, sig: bytes) -> bool:
    if len(msg_hash) != 32 or len(pubkey_x) != 32 or len(sig) != 64:
        return False
    try:
        P = C.point_from_x(C.int_from_bytes(pubkey_x), want_even_y=True)
        r = C.int_from_bytes(sig[:32])
        s = C.int_from_bytes(sig[32:])
        if r >= C.P or s >= C.N:
            return False
        e = C.int_from_bytes(
            tagged_hash("BIP0340/challenge", sig[:32] + pubkey_x + msg_hash)
        ) % C.N
        R = C.point_add(C.point_mul(C.G, s), C.point_mul(P, C.N - e))
        if R is None or not C.has_even_y(R) or R[0] != r:
            return False
        return True
    except (ValueError, ZeroDivisionError):
        return False
