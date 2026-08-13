"""hns-taproot: Taproot-style (BIP340/341 pattern) key- and script-path
spending applied to Handshake (HNS) name outputs.

See README.md for scope and docs/ARCHITECTURE.md for the design writeup.
"""
from .schnorr import generate_privkey, pubkey_from_privkey, sign, verify
from .mast import TapTree, TapLeaf
from .taproot import tweak_pubkey, tweak_privkey, output_from_internal_privkey, TaprootOutput
from .address import taproot_address, encode_segwit_address, decode_segwit_address
from .hns_covenant import (
    CovenantType,
    NameOutputSpec,
    RecoveryLeaf,
    TaprootNameOutput,
    simple_timelock_script,
    multisig_recovery_script,
    totp_recovery_leaves,
)
from .totp import (
    TotpLeafSet,
    hotp_code,
    totp_counter,
    derive_step_privkey,
    derive_step_pubkey,
    totp_leaf_script,
)

__version__ = "0.2.0"

__all__ = [
    "generate_privkey",
    "pubkey_from_privkey",
    "sign",
    "verify",
    "TapTree",
    "TapLeaf",
    "tweak_pubkey",
    "tweak_privkey",
    "output_from_internal_privkey",
    "TaprootOutput",
    "taproot_address",
    "encode_segwit_address",
    "decode_segwit_address",
    "CovenantType",
    "NameOutputSpec",
    "RecoveryLeaf",
    "TaprootNameOutput",
    "simple_timelock_script",
    "multisig_recovery_script",
    "totp_recovery_leaves",
    "TotpLeafSet",
    "hotp_code",
    "totp_counter",
    "derive_step_privkey",
    "derive_step_pubkey",
    "totp_leaf_script",
]
