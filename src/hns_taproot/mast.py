"""
MAST (Merkelized Alternative Script Tree) construction, following the
BIP341 tapleaf/tapbranch tagged-hash structure.

A tree is built from an ordered list of (leaf_version, script) pairs.
Leaves are combined pairwise (lexicographically sorted at each branch,
per BIP341) until a single merkle root remains. Each leaf also gets a
"control block" path of sibling hashes, used to prove inclusion without
revealing the rest of the tree.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schnorr import tagged_hash

LEAF_VERSION_DEFAULT = 0xC0


@dataclass
class TapLeaf:
    script: bytes
    leaf_version: int = LEAF_VERSION_DEFAULT

    def leaf_hash(self) -> bytes:
        return tagged_hash(
            "TapLeaf",
            bytes([self.leaf_version]) + _compact_size(len(self.script)) + self.script,
        )


@dataclass
class TapTree:
    leaves: list[TapLeaf] = field(default_factory=list)

    def add_leaf(self, script: bytes, leaf_version: int = LEAF_VERSION_DEFAULT) -> "TapTree":
        self.leaves.append(TapLeaf(script=script, leaf_version=leaf_version))
        return self

    def merkle_root(self) -> bytes:
        if not self.leaves:
            raise ValueError("tree has no leaves")
        level = [leaf.leaf_hash() for leaf in self.leaves]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(_branch_hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                nxt.append(level[-1])
            level = nxt
        return level[0]

    def control_path(self, leaf_index: int) -> list[bytes]:
        """Sibling hashes needed to prove `leaf_index` is in the tree."""
        if not (0 <= leaf_index < len(self.leaves)):
            raise IndexError("leaf_index out of range")
        level = [leaf.leaf_hash() for leaf in self.leaves]
        idx = leaf_index
        path: list[bytes] = []
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level) - 1, 2):
                if i == idx or i + 1 == idx:
                    sibling = level[i + 1] if i == idx else level[i]
                    path.append(sibling)
                nxt.append(_branch_hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                nxt.append(level[-1])
            idx //= 2
            level = nxt
        return path


def _branch_hash(a: bytes, b: bytes) -> bytes:
    lo, hi = (a, b) if a < b else (b, a)
    return tagged_hash("TapBranch", lo + hi)


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")
