"""
Handshake covenant model + a proposed Taproot-style output wrapper.

Background
----------
Every HNS name UTXO carries a "covenant" tagging what state-transition
the output represents (OPEN, BID, REVEAL, REDEEM, REGISTER, UPDATE,
RENEW, TRANSFER, FINALIZE, REVOKE, CLAIM). hsd enforces covenant
transition rules at the consensus layer; this module mirrors just the
type tags (matching hsd's `covenant.types`) so example transactions in
this repo read the same way they would against a real node.

What this module adds on top of that is *not* part of live HNS
consensus: it's a pattern for locking a name's controlling output
behind a Taproot-style key, so that:

  * the common case (an owner routinely doing TRANSFER -> FINALIZE,
    or an UPDATE/RENEW) spends via the *key path* -- one Schnorr
    signature, indistinguishable on-chain from any other spend, and
  * uncommon cases (a recovery key, an expiring fallback claim, a
    registrar-cosigned emergency revoke) live in the *script path* as
    MAST leaves that stay completely hidden unless actually used.

This is offered as a research/education pattern (see docs/ARCHITECTURE.md
for the rationale and the open questions around actually soft-forking
this into hsd), not a drop-in replacement for hsd's covenant scripts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .address import taproot_address, HRP_MAINNET
from .mast import TapTree
from .schnorr import pubkey_from_privkey
from .taproot import TaprootOutput, tweak_pubkey
from .totp import DEFAULT_STEP_SECONDS, DEFAULT_WINDOW, TotpLeafSet


class CovenantType(IntEnum):
    NONE = 0
    CLAIM = 1
    OPEN = 2
    BID = 3
    REVEAL = 4
    REDEEM = 5
    REGISTER = 6
    UPDATE = 7
    RENEW = 8
    TRANSFER = 9
    FINALIZE = 10
    REVOKE = 11


@dataclass
class RecoveryLeaf:
    """A named, human-readable script-path condition. `script` is a
    placeholder byte encoding standing in for a real HNS script program;
    swap in actual hsd opcodes if wiring this into a real covenant."""

    label: str
    script: bytes


@dataclass
class NameOutputSpec:
    name: str
    covenant: CovenantType
    owner_privkey: bytes
    recovery_leaves: list[RecoveryLeaf] = field(default_factory=list)
    totp: TotpLeafSet | None = None
    totp_at: int | None = None  # fixed timestamp for reproducible builds/tests; None = "now"
    hrp: str = HRP_MAINNET

    def build(self) -> "TaprootNameOutput":
        internal_pub = pubkey_from_privkey(self.owner_privkey)
        all_leaves = list(self.recovery_leaves)
        totp_leaf_offset = len(all_leaves)
        if self.totp is not None:
            all_leaves.extend(totp_recovery_leaves(self.totp, at=self.totp_at))

        tree = None
        root = None
        if all_leaves:
            tree = TapTree()
            for leaf in all_leaves:
                tree.add_leaf(leaf.script)
            root = tree.merkle_root()

        tro = tweak_pubkey(internal_pub, root)
        address = taproot_address(tro.output_pubkey, hrp=self.hrp)
        return TaprootNameOutput(
            name=self.name,
            covenant=self.covenant,
            taproot=tro,
            tree=tree,
            address=address,
            totp=self.totp,
            totp_leaf_offset=totp_leaf_offset if self.totp is not None else None,
        )


@dataclass
class TaprootNameOutput:
    name: str
    covenant: CovenantType
    taproot: TaprootOutput
    tree: TapTree | None
    address: str
    totp: TotpLeafSet | None = None
    totp_leaf_offset: int | None = None

    def has_recovery_paths(self) -> bool:
        return self.tree is not None and len(self.tree.leaves) > 0

    def totp_leaf_index_for_counter(self, counter: int, at: int | None = None) -> int:
        """Index into `self.tree.leaves` for a given TOTP step counter,
        for building that leaf's control-block/inclusion proof."""
        if self.totp is None or self.totp_leaf_offset is None:
            raise ValueError("this output has no TOTP leaves")
        return self.totp_leaf_offset + self.totp.leaf_index_for_counter(counter, at=at)

    def summary(self) -> str:
        lines = [
            f"name:            {self.name}",
            f"covenant:        {self.covenant.name}",
            f"internal pubkey: {self.taproot.internal_pubkey.hex()}",
            f"output pubkey:   {self.taproot.output_pubkey.hex()}",
            f"address:         {self.address}",
        ]
        if self.tree is not None:
            lines.append(f"merkle root:     {self.tree.merkle_root().hex()}")
            lines.append(f"recovery leaves: {len(self.tree.leaves)}")
        else:
            lines.append("recovery leaves: none (key-path only)")
        if self.totp is not None:
            lines.append(
                f"totp leaves:     {2 * self.totp.window + 1} "
                f"(+/-{self.totp.window} step(s) of {self.totp.step_seconds}s, "
                f"~{self.totp.step_seconds * (2 * self.totp.window + 1)}s tolerance window)"
            )
        return "\n".join(lines)


def simple_timelock_script(blocks: int) -> bytes:
    """Placeholder encoding for a relative-timelock recovery condition.
    Format: b'CSV' || little-endian u32 block count. Not a real hsd
    opcode sequence -- replace with actual script bytes to deploy."""
    return b"CSV" + blocks.to_bytes(4, "little")


def multisig_recovery_script(pubkeys_x: list[bytes], threshold: int) -> bytes:
    """Placeholder encoding for an m-of-n Schnorr recovery condition."""
    header = bytes([threshold, len(pubkeys_x)])
    return b"MULTI" + header + b"".join(pubkeys_x)


def totp_recovery_leaves(totp: TotpLeafSet, at: int | None = None) -> list[RecoveryLeaf]:
    """One `RecoveryLeaf` per time step in `totp`'s tolerance window, so
    a TOTP-gated recovery path can sit alongside timelock/multisig
    leaves in the same tree. See `totp.py` for the derivation, the time-
    sync/secret-management caveats, and why this is the covenant-
    compatible fallback to a full ZK construction rather than a
    substitute for one."""
    return [
        RecoveryLeaf(label=f"totp step {counter}", script=script)
        for counter, script in zip(totp.counters(at=at), totp.scripts(at=at))
    ]
