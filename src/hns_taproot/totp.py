"""
TOTP-gated recovery leaf for the MAST tree.

Idea
----
Alongside the timelock and multisig recovery leaves already in
`hns_covenant.py`, one leaf of the tree can require proof of a live
TOTP (RFC 6238) code instead of (or in addition to) a static recovery
key. This turns "I have my authenticator app" into a script-path
condition that stays hidden -- like every other leaf -- unless it's
actually the one invoked.

Why this can't just be "check the 6-digit code in script"
-----------------------------------------------------------
A script interpreter checking a decimal OTP string is awkward and,
worse, means the *code itself* -- not a signature over the spending
transaction -- is the witness. That's replayable by anyone who
observes it in the mempool before it's mined, and it doesn't bind the
proof to a specific transaction the way a signature does.

The fix used here is the same one TOTP-over-signatures schemes use:
derive a fresh, unrelated-looking Schnorr keypair for every time step
from an HMAC of the shared secret and the step counter, and let the
leaf require a normal Schnorr signature from *that step's* key. Proving
"I know the current code" and proving "I can sign with the current
step's key" become the same statement, but the on-chain witness is a
signature over the actual spending transaction, not a bare code.

    privkey_t = HMAC-SHA256(secret, "HNS-TOTP-LEAF" || step_counter) mod n
    pubkey_t  = privkey_t * G

Each step's `pubkey_t` is baked into its own MAST leaf at tree-build
time (see `TotpLeafSet`). At spend time the owner reveals only the one
leaf whose step is current, exactly like revealing a timelock or
multisig leaf -- the other, unused step-keys stay hidden inside the
Merkle root along with every other condition that wasn't invoked.

Two problems this does NOT solve on its own -- read before using
------------------------------------------------------------------
1. **Time synchronization.** The tree has to be built with a *window*
   of steps around "now" (`TotpLeafSet.window`) because the signer's
   clock, the node relaying the transaction, and block time itself are
   never perfectly aligned. Too narrow a window and a legitimate spend
   gets rejected for landing one step late; too wide a window and you've
   quietly reintroduced a longer-lived secret-guessing surface. This
   repo defaults to +/-1 step (i.e. valid for ~90 seconds at the default
   30s step), matching typical TOTP client tolerance -- tune for your
   actual expected clock drift and mempool/confirmation delay, not for
   this default blindly.
2. **Secret management.** `secret` here plays the same role as a TOTP
   seed in any authenticator app: whoever holds it can derive every
   past and future step key. It needs the same handling real TOTP
   seeds need (secure enclave / HSM, never logged, rotated on suspected
   compromise) *plus* the awareness that -- unlike a normal 2FA app
   protecting a login -- compromise here is a compromise of a
   name-ownership recovery path. Treat it as key material, not as a
   convenience secret.

Why ZK proofs are the "real" answer, and why covenants still work without them
--------------------------------------------------------------------------------
This scheme still reveals, at spend time, exactly *which* time-step
leaf fired and the pubkey/signature for it -- an observer watching the
mempool learns "this owner's TOTP path was used just now," even though
they learn nothing about the secret itself or the other leaves. A zero-
knowledge proof of "I know a secret and a step such that
HMAC(secret, step) derives a key that signs this transaction, and step
is within the current window" would hide even that: the witness would
be a proof, not a distinguishable signature/pubkey pair, so a TOTP-
gated spend would be indistinguishable from any other script-path (or
even key-path) spend. That's a strictly stronger privacy and
anti-replay property than the leaf-per-step approach here, at the cost
of needing a circuit and a proving system HNS's script interpreter
doesn't have today.

None of that blocks using this pattern with covenants as they exist:
the leaf-per-step construction above is pure Schnorr + MAST, wraps
into `NameOutputSpec` exactly like the timelock/multisig leaves, and
needs nothing from hsd that the rest of this repo doesn't already
assume. ZK is the upgrade path if/when a proving system is available;
it is not a precondition for shipping the simpler version.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

from . import secp256k1 as C
from .schnorr import pubkey_from_privkey, sign, verify

DEFAULT_STEP_SECONDS = 30
DEFAULT_DIGITS = 6
DEFAULT_WINDOW = 1

LEAF_TAG = b"TOTP"


def hotp_code(secret: bytes, counter: int, digits: int = DEFAULT_DIGITS) -> str:
    """RFC 4226 HOTP value -- the human-facing code an authenticator app
    would display for this counter. Not used on-chain; useful only for
    cross-checking a step against a normal TOTP app during setup/testing."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def totp_counter(step_seconds: int = DEFAULT_STEP_SECONDS, at: int | None = None) -> int:
    t = int(time.time()) if at is None else at
    return t // step_seconds


def derive_step_privkey(secret: bytes, counter: int) -> bytes:
    """The on-chain-relevant primitive: a deterministic, otherwise
    unrelated-looking Schnorr private key for one TOTP time step."""
    d = hmac.new(secret, LEAF_TAG + struct.pack(">Q", counter), hashlib.sha256).digest()
    d_int = (C.int_from_bytes(d) % (C.N - 1)) + 1
    return d_int.to_bytes(32, "big")


def derive_step_pubkey(secret: bytes, counter: int) -> bytes:
    return pubkey_from_privkey(derive_step_privkey(secret, counter))


def totp_leaf_script(pubkey_x: bytes) -> bytes:
    """Placeholder encoding for a script-path leaf that checks a Schnorr
    signature against one time-step's pubkey. Format: b'TOTP' || x-only
    pubkey (32 bytes). Swap for a real CHECKSIG-style opcode sequence to
    deploy against an actual covenant output -- same caveat as the other
    placeholder scripts in `hns_covenant.py`."""
    if len(pubkey_x) != 32:
        raise ValueError("pubkey_x must be 32 bytes")
    return LEAF_TAG + pubkey_x


@dataclass
class TotpLeafSet:
    """A window of TOTP leaves around 'now'. Building the tree with a
    window (rather than a single current-step leaf) is what makes the
    recovery path survive realistic clock drift between the signer's
    device, the relaying node, and confirmation time -- see the module
    docstring for the tradeoff this involves."""

    secret: bytes
    step_seconds: int = DEFAULT_STEP_SECONDS
    window: int = DEFAULT_WINDOW

    def counters(self, at: int | None = None) -> list[int]:
        center = totp_counter(self.step_seconds, at=at)
        return [center + i for i in range(-self.window, self.window + 1)]

    def scripts(self, at: int | None = None) -> list[bytes]:
        return [totp_leaf_script(derive_step_pubkey(self.secret, c)) for c in self.counters(at=at)]

    def sign_for_now(self, msg_hash: bytes, at: int | None = None) -> tuple[int, bytes]:
        """Sign with the current step's key -- the step an authenticator
        app's live code corresponds to right now. Returns
        `(counter, signature)`; the spender needs the counter to know
        which leaf in the window to reveal via `mast.TapTree.control_path`."""
        counter = totp_counter(self.step_seconds, at=at)
        return counter, sign(msg_hash, derive_step_privkey(self.secret, counter))

    def verify_for_counter(self, msg_hash: bytes, counter: int, sig: bytes) -> bool:
        return verify(msg_hash, derive_step_pubkey(self.secret, counter), sig)

    def leaf_index_for_counter(self, counter: int, at: int | None = None) -> int:
        """Index of `counter`'s leaf within `self.scripts()`'s output,
        for locating it in the built `TapTree`."""
        counters = self.counters(at=at)
        return counters.index(counter)
