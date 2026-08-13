import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot import schnorr
from hns_taproot.mast import TapTree
from hns_taproot.taproot import tweak_pubkey, tweak_privkey, output_from_internal_privkey
from hns_taproot.hns_covenant import (
    CovenantType,
    NameOutputSpec,
    RecoveryLeaf,
    simple_timelock_script,
)


def test_tweaked_privkey_matches_tweaked_pubkey_key_path_spend():
    internal_priv = schnorr.generate_privkey()
    tro = output_from_internal_privkey(internal_priv, tree=None)

    # Derive the private key for the tweaked (output) key and sign with it.
    tweaked_priv = tweak_privkey(internal_priv, merkle_root=None)
    msg = hashlib.sha256(b"key path spend").digest()
    sig = schnorr.sign(msg, tweaked_priv)

    assert schnorr.verify(msg, tro.output_pubkey, sig)


def test_script_path_changes_output_key():
    internal_priv = schnorr.generate_privkey()
    internal_pub = schnorr.pubkey_from_privkey(internal_priv)

    no_script = tweak_pubkey(internal_pub, merkle_root=None)

    tree = TapTree().add_leaf(simple_timelock_script(1000))
    with_script = tweak_pubkey(internal_pub, merkle_root=tree.merkle_root())

    assert no_script.output_pubkey != with_script.output_pubkey


def test_name_output_spec_key_path_only():
    priv = schnorr.generate_privkey()
    spec = NameOutputSpec(name="example", covenant=CovenantType.TRANSFER, owner_privkey=priv)
    out = spec.build()
    assert not out.has_recovery_paths()
    assert out.address.startswith("hs1p")


def test_name_output_spec_with_recovery_leaf():
    priv = schnorr.generate_privkey()
    recovery_priv = schnorr.generate_privkey()
    recovery_pub = schnorr.pubkey_from_privkey(recovery_priv)

    from hns_taproot.hns_covenant import multisig_recovery_script

    spec = NameOutputSpec(
        name="example",
        covenant=CovenantType.TRANSFER,
        owner_privkey=priv,
        recovery_leaves=[
            RecoveryLeaf(label="90-day timelock fallback", script=simple_timelock_script(12960)),
            RecoveryLeaf(
                label="2-of-2 registrar recovery",
                script=multisig_recovery_script([recovery_pub, recovery_pub], threshold=2),
            ),
        ],
    )
    out = spec.build()
    assert out.has_recovery_paths()
    assert len(out.tree.leaves) == 2
