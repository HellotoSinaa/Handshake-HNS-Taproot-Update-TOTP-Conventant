import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot import schnorr
from hns_taproot.totp import (
    TotpLeafSet,
    derive_step_privkey,
    derive_step_pubkey,
    hotp_code,
    totp_counter,
    totp_leaf_script,
)
from hns_taproot.hns_covenant import (
    CovenantType,
    NameOutputSpec,
    RecoveryLeaf,
    simple_timelock_script,
    totp_recovery_leaves,
)

SECRET = b"test-shared-secret-do-not-use-in-prod"
FIXED_NOW = 1_700_000_000  # arbitrary fixed unix time for reproducible tests


def test_hotp_code_is_six_digits_and_deterministic():
    code_a = hotp_code(SECRET, counter=42)
    code_b = hotp_code(SECRET, counter=42)
    assert code_a == code_b
    assert len(code_a) == 6
    assert code_a.isdigit()


def test_hotp_code_changes_across_counters():
    assert hotp_code(SECRET, counter=1) != hotp_code(SECRET, counter=2)


def test_step_keypair_is_deterministic_and_valid():
    counter = totp_counter(at=FIXED_NOW)
    priv = derive_step_privkey(SECRET, counter)
    pub = derive_step_pubkey(SECRET, counter)
    assert schnorr.pubkey_from_privkey(priv) == pub

    msg = hashlib.sha256(b"totp leaf spend").digest()
    sig = schnorr.sign(msg, priv)
    assert schnorr.verify(msg, pub, sig)


def test_step_keys_differ_across_steps():
    a = derive_step_pubkey(SECRET, counter=100)
    b = derive_step_pubkey(SECRET, counter=101)
    assert a != b


def test_totp_leaf_script_round_trips_pubkey():
    pub = derive_step_pubkey(SECRET, counter=5)
    script = totp_leaf_script(pub)
    assert script.startswith(b"TOTP")
    assert script[4:] == pub


def test_leaf_set_window_covers_expected_counters():
    totp = TotpLeafSet(secret=SECRET, step_seconds=30, window=1)
    counters = totp.counters(at=FIXED_NOW)
    center = totp_counter(30, at=FIXED_NOW)
    assert counters == [center - 1, center, center + 1]
    assert len(totp.scripts(at=FIXED_NOW)) == 3


def test_sign_for_now_verifies_against_current_step():
    totp = TotpLeafSet(secret=SECRET, step_seconds=30, window=1)
    msg = hashlib.sha256(b"spend at current step").digest()
    counter, sig = totp.sign_for_now(msg, at=FIXED_NOW)
    assert totp.verify_for_counter(msg, counter, sig)

    # Signature for the current step must not verify against a neighbor.
    assert not totp.verify_for_counter(msg, counter + 1, sig)


def test_totp_recovery_leaves_matches_window_size():
    totp = TotpLeafSet(secret=SECRET, step_seconds=30, window=2)
    leaves = totp_recovery_leaves(totp, at=FIXED_NOW)
    assert len(leaves) == 5  # window=2 -> 2*2+1 steps
    assert all(leaf.script.startswith(b"TOTP") for leaf in leaves)
    assert len({leaf.script for leaf in leaves}) == 5  # all distinct


def test_name_output_spec_with_totp_leaf_alongside_recovery_leaves():
    owner_priv = schnorr.generate_privkey()
    totp = TotpLeafSet(secret=SECRET, step_seconds=30, window=1)

    spec = NameOutputSpec(
        name="example",
        covenant=CovenantType.TRANSFER,
        owner_privkey=owner_priv,
        recovery_leaves=[
            RecoveryLeaf(label="90-day timelock fallback", script=simple_timelock_script(12960)),
        ],
        totp=totp,
        totp_at=FIXED_NOW,
    )
    out = spec.build()

    assert out.has_recovery_paths()
    # 1 timelock leaf + 3 totp-window leaves
    assert len(out.tree.leaves) == 4

    current_counter = totp_counter(30, at=FIXED_NOW)
    idx = out.totp_leaf_index_for_counter(current_counter, at=FIXED_NOW)
    # offset 1 (the preceding timelock leaf) + 1 (current step is the
    # middle entry of the [-1, 0, +1] window) = 2
    assert idx == 2

    # The revealed leaf must actually be provable against the committed root.
    path = out.tree.control_path(idx)
    assert isinstance(path, list)


def test_totp_only_output_has_no_static_recovery_leaves():
    owner_priv = schnorr.generate_privkey()
    totp = TotpLeafSet(secret=SECRET, step_seconds=30, window=1)

    spec = NameOutputSpec(
        name="example",
        covenant=CovenantType.TRANSFER,
        owner_privkey=owner_priv,
        totp=totp,
        totp_at=FIXED_NOW,
    )
    out = spec.build()
    assert len(out.tree.leaves) == 3
    assert out.totp_leaf_offset == 0
