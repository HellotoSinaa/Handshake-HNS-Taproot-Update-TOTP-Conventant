"""
Minimal pure-Python secp256k1 field/curve arithmetic.

This is intentionally dependency-free so the rest of the library can run
anywhere Python runs. It implements only what BIP340 (Schnorr) and
BIP341-style tweaking need: point addition/doubling, scalar multiplication,
point lifting from an x-only coordinate, and jacobi-symbol based
"has even y" checks.

Not constant-time. Do not use this for signing with real-value keys in a
production/hostile environment -- swap in `coincurve` / libsecp256k1
bindings for anything that touches real funds. This module exists for
clarity, testability, and portability of the reference logic.
"""
from __future__ import annotations

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
G = (Gx, Gy)

Point = tuple  # (x, y) or None for infinity


def _mod_inverse(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def is_infinity(p) -> bool:
    return p is None


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 * _mod_inverse(2 * y1, P)) % P
    else:
        lam = ((y2 - y1) * _mod_inverse((x2 - x1) % P, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(p, scalar: int):
    scalar %= N
    result = None
    addend = p
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def point_from_x(x: int, want_even_y: bool = True):
    """Lift an x-only coordinate to a full point with even y (BIP340)."""
    if x >= P:
        raise ValueError("x coordinate out of field range")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("x is not a valid coordinate on the curve")
    if want_even_y and y % 2 != 0:
        y = P - y
    elif not want_even_y and y % 2 == 0:
        y = P - y
    return (x, y)


def has_even_y(p) -> bool:
    return p[1] % 2 == 0


def bytes_from_point(p) -> bytes:
    return p[0].to_bytes(32, "big")


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, "big")


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")
