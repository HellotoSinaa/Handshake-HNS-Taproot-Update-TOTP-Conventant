"""
Demo: wrap a `learnhns.com` name's TRANSFER output behind a Taproot-style
key with two hidden recovery paths -- a 90-day timelock fallback and a
TOTP-gated leaf -- then walk through spending via the TOTP path.

Run with:  python examples/demo_totp_recovery.py
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot import schnorr
from hns_taproot.hns_covenant import CovenantType, NameOutputSpec, RecoveryLeaf, simple_timelock_script
from hns_taproot.taproot import build_control_block
from hns_taproot.totp import TotpLeafSet, hotp_code, totp_counter


def main():
    owner_priv = schnorr.generate_privkey()

    # In practice this is provisioned once, shown to the owner as a QR
    # code (same enrollment flow as any authenticator app), and then
    # stored the way any TOTP seed / key material should be -- see the
    # "Secret management" section of totp.py's module docstring.
    totp_secret = schnorr.generate_privkey()  # 32 random bytes stands in for a TOTP seed
    totp = TotpLeafSet(secret=totp_secret, step_seconds=30, window=1)

    spec = NameOutputSpec(
        name="learnhns",
        covenant=CovenantType.TRANSFER,
        owner_privkey=owner_priv,
        recovery_leaves=[
            RecoveryLeaf(
                label="90-day timelock fallback claim",
                script=simple_timelock_script(blocks=12960),
            ),
        ],
        totp=totp,
    )
    output = spec.build()

    print("=== Taproot-wrapped HNS name output (timelock leaf + TOTP window) ===")
    print(output.summary())
    print()

    # --- What the owner's authenticator app would show right now ---
    now_counter = totp_counter(totp.step_seconds)
    print("=== Authenticator app view (for comparison only, not used on-chain) ===")
    print(f"current 6-digit code: {hotp_code(totp_secret, now_counter)}")
    print(
        "The on-chain leaf doesn't check this code directly -- it checks a "
        "signature from the Schnorr key deterministically derived from the "
        "same (secret, time-step) pair. See totp.py for why."
    )
    print()

    # --- Script-path spend via the TOTP leaf ---
    msg = hashlib.sha256(b"spend: name=learnhns covenant=FINALIZE via totp-recovery").digest()
    counter, sig = totp.sign_for_now(msg)
    leaf_index = output.totp_leaf_index_for_counter(counter)

    control_block = build_control_block(
        internal_pubkey_x=output.taproot.internal_pubkey,
        tree=output.tree,
        leaf_index=leaf_index,
        output_parity_even=output.taproot.output_parity_even,
    )

    print("=== Script-path spend (TOTP leaf revealed) ===")
    print(f"time step counter:    {counter}")
    print(f"revealed leaf script: {output.tree.leaves[leaf_index].script.hex()}")
    print(f"signature valid:      {totp.verify_for_counter(msg, counter, sig)}")
    print(f"control block ({len(control_block)} bytes): {control_block.hex()}")
    print()
    print(
        "Only this one time-step leaf and its sibling hashes are revealed. "
        "The timelock leaf, and every other step in the TOTP window, stay "
        "hidden inside the merkle root -- exactly like an unused branch in "
        "any other MAST tree."
    )


if __name__ == "__main__":
    main()
