"""
Bech32 / Bech32m address encoding for Handshake-style witness programs.

Handshake mainnet addresses use the "hs" human-readable prefix with
witness v0 (P2WPKH/P2WSH) encoded via plain Bech32. This module adds
support for encoding a *hypothetical* witness v1 (Taproot-style) output
using Bech32m, per BIP350 -- HNS consensus does not currently define a
v1 witness program; this is provided purely so the rest of the library
can round-trip addresses for demo/test purposes.

Network HRPs (matching hsd):
    mainnet -> "hs"
    testnet -> "ts"
    regtest -> "rs"
    simnet  -> "ss"
"""
from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3

HRP_MAINNET = "hs"
HRP_TESTNET = "ts"
HRP_REGTEST = "rs"
HRP_SIMNET = "ss"


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp: str, data: list[int], const: int) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid data for base conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in base conversion")
    return ret


def encode_segwit_address(hrp: str, witness_version: int, witness_program: bytes) -> str:
    if not (0 <= witness_version <= 16):
        raise ValueError("witness version out of range")
    const = BECH32_CONST if witness_version == 0 else BECH32M_CONST
    data = [witness_version] + _convertbits(witness_program, 8, 5, True)
    checksum = _create_checksum(hrp, data, const)
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def decode_segwit_address(hrp: str, address: str) -> tuple[int, bytes]:
    if not address.startswith(hrp + "1"):
        raise ValueError("hrp mismatch")
    data_part = address[len(hrp) + 1 :]
    data = [CHARSET.find(c) for c in data_part]
    if -1 in data:
        raise ValueError("invalid character in address")
    values = data[:-6]
    checksum = data[-6:]
    witness_version = values[0]
    const = BECH32_CONST if witness_version == 0 else BECH32M_CONST
    if _polymod(_hrp_expand(hrp) + values + checksum) != const:
        raise ValueError("invalid checksum")
    witness_program = bytes(_convertbits(values[1:], 5, 8, False))
    return witness_version, witness_program


def taproot_address(output_pubkey_x: bytes, hrp: str = HRP_MAINNET) -> str:
    """Encode a witness-v1 (Taproot-style) address. See module docstring:
    this witness version is not part of live HNS consensus."""
    if len(output_pubkey_x) != 32:
        raise ValueError("taproot output key must be 32 bytes (x-only)")
    return encode_segwit_address(hrp, 1, output_pubkey_x)
