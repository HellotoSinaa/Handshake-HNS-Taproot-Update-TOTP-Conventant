# hns-taproot

Taproot-style key-path / script-path spending (BIP340 Schnorr + BIP341-pattern
MAST tweaking) applied to [Handshake (HNS)](https://handshake.org) name
outputs, in pure Python.

Companion code for the write-up on [learnhns.com](https://learnhns.com).

## What's actually in here

- **`schnorr.py`** — BIP340-style Schnorr signature generation/verification
  over secp256k1 (tagged hashing, nonce derivation, x-only pubkeys).
- **`mast.py`** — Merkelized Alternative Script Tree construction: tapleaf /
  tapbranch tagged hashing, merkle root computation, and control-block
  (inclusion proof) generation for a chosen leaf.
- **`taproot.py`** — tweaks an internal public key with a MAST root to
  produce a single output key (`Q = P + hash(P || root)·G`), and derives the
  matching tweaked private key for key-path spends.
- **`address.py`** — Bech32 / Bech32m encoding matching hsd's HRPs
  (`hs` mainnet / `ts` testnet / `rs` regtest / `ss` simnet).
- **`hns_covenant.py`** — models HNS's covenant types (OPEN, BID, REVEAL,
  REGISTER, TRANSFER, FINALIZE, etc., matching hsd's `covenant.types`) and
  wraps a name's controlling output in a Taproot-style key, with optional
  hidden recovery leaves (timelocked fallback claim, multisig recovery,
  TOTP-gated recovery, ...).
- **`totp.py`** — a TOTP-gated (RFC 6238-style) recovery leaf: each time
  step gets its own deterministically-derived Schnorr keypair, so "prove
  you have the live authenticator code" becomes an ordinary script-path
  MAST leaf instead of a bare, replayable 6-digit code. See the module
  docstring for the time-sync and secret-management tradeoffs, and why
  a ZK proof (not implemented here) is the strictly-stronger version of
  this same idea.
- **`secp256k1.py`** — the underlying pure-Python field/curve arithmetic
  everything else is built on.

All the cryptographic building blocks (Schnorr signing/verification, MAST
tree hashing, key tweaking, TOTP leaf derivation) are fully functional and
covered by tests. Run them yourself, don't take it on faith:

```bash
pip install -r requirements.txt
pytest tests/ -v
python examples/demo_name_transfer_taproot.py
python examples/demo_totp_recovery.py
```

## Scope — please read before assuming this is "live"

**Taproot is not part of HNS consensus today.** hsd does not currently
define a witness-v1 program or recognize BIP340/341-style spends. Nothing
in this repo can construct a transaction hsd will accept on mainnet.

What this repo *is*: a working reference implementation of the primitives
(Schnorr signatures, MAST, key tweaking) plus a proposed pattern for how
they could wrap HNS's existing covenant model — giving name owners a single
indistinguishable key-path spend for routine operations (TRANSFER, UPDATE,
RENEW, FINALIZE) while keeping conditional recovery paths (timelocks,
registrar-cosigned recovery, multisig fallback) hidden in a MAST tree unless
they're actually invoked. That's the same privacy/flexibility trade Bitcoin
made with BIP340/341/342 — explored here in the context of name ownership
rather than coin ownership.

If you want to take this further (actually proposing a soft fork, wiring
real hsd script opcodes into the recovery leaves instead of the placeholder
encodings in `hns_covenant.py`), see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the open questions, including where the TOTP leaf's time-sync and
secret-management tradeoffs fit and why a ZK-proof version is the real
end state for that particular leaf.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick example

```python
from hns_taproot import schnorr
from hns_taproot.hns_covenant import CovenantType, NameOutputSpec, RecoveryLeaf, simple_timelock_script
from hns_taproot.totp import TotpLeafSet

owner_priv = schnorr.generate_privkey()
totp_secret = schnorr.generate_privkey()  # provisioned once, handled like any TOTP seed

spec = NameOutputSpec(
    name="learnhns",
    covenant=CovenantType.TRANSFER,
    owner_privkey=owner_priv,
    recovery_leaves=[
        RecoveryLeaf(label="90-day timelock fallback", script=simple_timelock_script(12960)),
    ],
    totp=TotpLeafSet(secret=totp_secret, step_seconds=30, window=1),
)
output = spec.build()
print(output.summary())
```

See [`examples/demo_totp_recovery.py`](examples/demo_totp_recovery.py) for
the full flow: building the tree, deriving the current step's key, signing,
and revealing just that one leaf via a control block.

## Security note

The curve arithmetic in `secp256k1.py` is written for clarity and is **not
constant-time**. It's fine for learning, testing, and generating example
transactions with throwaway keys. Do not use it to sign for keys that hold
real value — use `libsecp256k1` bindings (e.g. `coincurve`) for that.

## License

MIT — see `LICENSE`.
