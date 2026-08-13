import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot import schnorr


def test_sign_and_verify_roundtrip():
    priv = schnorr.generate_privkey()
    pub = schnorr.pubkey_from_privkey(priv)
    msg = hashlib.sha256(b"hns taproot test message").digest()
    sig = schnorr.sign(msg, priv)
    assert schnorr.verify(msg, pub, sig)


def test_verify_rejects_wrong_message():
    priv = schnorr.generate_privkey()
    pub = schnorr.pubkey_from_privkey(priv)
    msg = hashlib.sha256(b"message a").digest()
    other = hashlib.sha256(b"message b").digest()
    sig = schnorr.sign(msg, priv)
    assert not schnorr.verify(other, pub, sig)


def test_verify_rejects_wrong_key():
    priv1 = schnorr.generate_privkey()
    priv2 = schnorr.generate_privkey()
    pub2 = schnorr.pubkey_from_privkey(priv2)
    msg = hashlib.sha256(b"hns taproot test message").digest()
    sig = schnorr.sign(msg, priv1)
    assert not schnorr.verify(msg, pub2, sig)


def test_deterministic_with_fixed_aux_rand():
    priv = schnorr.generate_privkey()
    msg = hashlib.sha256(b"fixed").digest()
    aux = b"\x00" * 32
    sig1 = schnorr.sign(msg, priv, aux_rand=aux)
    sig2 = schnorr.sign(msg, priv, aux_rand=aux)
    assert sig1 == sig2
