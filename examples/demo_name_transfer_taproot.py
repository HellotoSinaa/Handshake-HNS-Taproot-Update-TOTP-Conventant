"""
Demo: wrap a `learnhns.com` name's TRANSFER output behind a Taproot-style
key, with one hidden recovery leaf (a 90-day relative-timelock fallback).

Run with:  python examples/demo_name_transfer_taproot.py
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot import schnorr
from hns_taproot.hns_covenant import CovenantType, NameOutputSpec, RecoveryLeaf, simple_timelock_script
from hns_taproot.mast import TapTree
from hns_taproot.taproot import build_control_block, tweak_privkey


def main():
    owner_priv = schnorr.generate_privkey()

    spec = NameOutputSpec(
        name="learnhns",
        covenant=CovenantType.TRANSFER,
        owner_privkey=owner_priv,
        recovery_leaves=[
            RecoveryLeaf(
                label="90-day timelock fallback claim",
                script=simple_timelock_script(blocks=12960),  # ~90 days at 10-min blocks
            ),
        ],
    )
    output = spec.build()

    print("=== Taproot-wrapped HNS name output ===")
    print(output.summary())
    print()

    # --- Key-path spend (the common case: routine owner transfer) ---
    tweaked_priv = tweak_privkey(owner_priv, merkle_root=output.tree.merkle_root())
    msg = hashlib.sha256(b"spend: name=learnhns covenant=FINALIZE").digest()
    sig = schnorr.sign(msg, tweaked_priv)
    valid = schnorr.verify(msg, output.taproot.output_pubkey, sig)
    print("=== Key-path spend (owner signs directly) ===")
    print(f"signature valid: {valid}")
    print()

    # --- Script-path spend (recovery leaf revealed + proven via control block) ---
    from hns_taproot.address import HRP_MAINNET  # noqa: F401 (kept for readability)

    control_block = build_control_block(
        internal_pubkey_x=output.taproot.internal_pubkey,
        tree=output.tree,
        leaf_index=0,
        output_parity_even=output.taproot.output_parity_even,
    )
    print("=== Script-path spend (recovery leaf revealed) ===")
    print(f"revealed leaf script: {output.tree.leaves[0].script}")
    print(f"control block ({len(control_block)} bytes): {control_block.hex()}")
    print(
        "A verifier recomputes the merkle root from the leaf + control block "
        "siblings, re-tweaks the internal key with that root, and checks it "
        "equals the output key -- without ever seeing the other leaves."
    )


if __name__ == "__main__":
    main()
