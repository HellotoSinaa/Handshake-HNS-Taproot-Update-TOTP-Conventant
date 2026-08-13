# Architecture

## Why look at Taproot for HNS at all

Bitcoin's Taproot upgrade (BIP340/341/342) solved a specific problem: most
spends are the "boring" cooperative case (single signer, or a cooperative
multisig collapsed via MuSig), but a UTXO's script often has to account for
uncommon cases too (timelocked recovery, multisig fallback, escrow). Before
Taproot, every one of those conditions had to be visible in the scriptPubKey
or witness, whether or not it was ever used — a privacy leak and a fee cost.
Taproot's fix: commit to *all* the conditions in a Merkle tree, but only
reveal the branch actually used. The common case (key path) reveals nothing
extra at all — it looks like a single-sig spend no matter how complex the
underlying policy is.

HNS name ownership has the same shape. A name's controlling output changes
hands via routine covenant transitions (`TRANSFER` → `FINALIZE`, `UPDATE`,
`RENEW`) that ideally look identical on-chain and cost the minimum, but an
owner may reasonably want:

- a **timelocked fallback** claim path (e.g. "if this key is inactive for
  90 days, a backup key can reclaim the name"),
- a **registrar- or guardian-cosigned recovery** path for lost-key scenarios,
  without giving that cosigner day-to-day control,
- an **emergency revoke** path distinct from the owner's normal key.

Today, doing any of this on HNS means either not doing it, or building it
as an out-of-band custody arrangement that isn't enforced by the chain at
all. A MAST-wrapped output makes those conditions chain-enforced *and*
invisible until invoked.

## What this repo implements vs. what a real deployment needs

| Piece | Status here | What's needed for real deployment |
|---|---|---|
| Schnorr sign/verify (BIP340) | Implemented, tested | Same math; hsd/consensus would need script-interpreter support for a new sighash + verification opcode |
| MAST tree + control blocks | Implemented, tested | Same construction; needs a canonical serialization matching whatever HNS opcodes encode leaf scripts |
| Key tweaking (BIP341-style) | Implemented, tested | Same; the open design question is whether HNS wants BIP341's exact tweak formula or a variant tied to covenant type |
| Witness-v1 address encoding | Implemented (Bech32m) | HNS would need to reserve a witness version + update hsd's address parser |
| Recovery leaf scripts (`simple_timelock_script`, `multisig_recovery_script`, `totp_leaf_script`) | Placeholder byte encodings | Real hsd opcode sequences (CSV-equivalent, multisig `CHECKMULTISIG`-equivalent, Schnorr `CHECKSIG`-equivalent for the TOTP step key) once/if consensus support exists |
| Covenant transition enforcement | Not touched | This repo only wraps the *output key*; covenant validity (is this actually a legal TRANSFER given the current name state) stays exactly as hsd already enforces it — this is additive, not a replacement |

## TOTP as a MAST leaf: an alternative recovery path

Alongside the timelock and multisig recovery leaves, a MAST tree leaf can
require proof of a live TOTP (RFC 6238) code — the same primitive behind
any authenticator app — instead of a static recovery key. `totp.py`
implements this the same way this repo implements everything else: real
math, not a stub. The construction, in short:

- Derive a fresh Schnorr keypair per time step:
  `privkey_t = HMAC-SHA256(secret, "HNS-TOTP-LEAF" || step_counter) mod n`.
- Bake each step's `pubkey_t` into its own leaf (`totp_leaf_script`) for a
  window of steps around "now" (`TotpLeafSet`), so the tree tolerates
  realistic clock drift.
- At spend time, the owner signs with the current step's key and reveals
  only that one leaf — exactly like revealing a timelock or multisig
  branch. Every other step and every other leaf stays hidden in the root.

This is deliberately *not* "check a 6-digit code in script." A bare code
would be the witness itself — replayable by anyone who observes it before
confirmation, and not bound to a specific spending transaction. Requiring
a signature over the transaction fixes both problems while keeping the
same "prove you hold the live TOTP secret" property.

### Time synchronization

The tree has to commit to a *window* of steps, not just the single step
valid "right now," because the signer's clock, the relaying node, and
confirmation time are never perfectly aligned. `TotpLeafSet.window`
controls that tolerance (default ±1 step, i.e. ~90 seconds at the default
30-second step). This is a real tradeoff, not a default to leave alone:

- **Too narrow** — a legitimate spend can get rejected for landing one
  step late, especially if there's any mempool delay between signing and
  confirmation.
- **Too wide** — every extra step is an extra pre-committed leaf, meaning
  more of the tree's shape is fixed in advance and more valid signing
  keys exist concurrently, which widens (slightly) the practical window
  during which a leaked step-key remains useful.

Pick the window based on the actual expected clock drift and confirmation
delay for the deployment, not by copying the default.

### Secret management

The TOTP `secret` plays the same role as any authenticator app's seed:
whoever holds it can derive every past and future step's private key. It
needs the handling any TOTP seed needs — secure enclave / HSM storage,
never logged, rotated on suspected compromise — *plus* the awareness that
compromise here isn't "someone can log into an account," it's "someone
can reconstruct a name-ownership recovery path." Provisioning (how the
secret reaches the owner's authenticator app in the first place) is a real
part of the design, not an afterthought — treat the enrollment flow with
the same care as generating `owner_privkey`.

### Why ZK proofs are the real fix, and why this still works without them

The leaf-per-step construction still leaks metadata at spend time: an
observer watching the mempool learns "this owner's TOTP path fired just
now," even though they learn nothing about the secret or the unused
leaves. A zero-knowledge proof of *"I know a secret and a step such that
HMAC(secret, step) derives a key that signs this transaction, and step is
within the current window"* would hide even that — the witness becomes a
proof rather than a distinguishable pubkey/signature pair, so a TOTP-gated
spend would be indistinguishable from any other script-path (or key-path)
spend. That's a strictly stronger privacy and anti-replay property than
what's implemented here, and it's the right long-term target if HNS ever
gets a proving system in its script interpreter.

It is not, however, a precondition for using this pattern today. The
leaf-per-step version is pure Schnorr + MAST — it composes with
`NameOutputSpec` exactly like the timelock and multisig leaves already do,
and needs nothing from hsd beyond what the rest of this repo already
assumes (see the primitives table above). ZK is the upgrade path; the
covenant-compatible version ships now.

## Open questions for anyone taking this further

1. **Soft fork vs. sidechain vs. off-chain custody layer.** Changing hsd's
   consensus rules to recognize a new witness version is a real soft fork;
   worth weighing against building this as a custody convention on top of
   existing multisig-style covenant scripts instead.
2. **Sighash design.** BIP341 introduced a new sighash algorithm alongside
   Schnorr. HNS's existing sighash would need review for whether it already
   composes safely with Schnorr signing or needs its own update.
3. **Fee/weight accounting.** Part of Taproot's appeal on Bitcoin is
   witness discount weighting. HNS's fee model would need an equivalent
   story for this to actually be cheaper than the status quo, not just more
   private.
4. **Leaf script language.** This repo's placeholder leaf scripts
   (`CSV`-prefixed timelock, `MULTI`-prefixed multisig, `TOTP`-prefixed
   step-key check) are stand-ins. A real proposal needs actual opcode
   sequences hsd's script interpreter can execute.
5. **ZK upgrade path for the TOTP leaf.** The leaf-per-step TOTP
   construction reveals which step fired at spend time. Replacing it with
   a zero-knowledge proof of "I know a secret and current step" would hide
   that too, but needs a circuit and a proving system HNS's script
   interpreter doesn't have today — worth scoping alongside whatever
   general-purpose script upgrade eventually lands, rather than as a
   TOTP-specific special case.

None of this is a promise that HNS will or should adopt Taproot — it's a
working sketch of what the primitives look like if it did, so the trade-offs
above can be discussed concretely instead of abstractly.
