import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hns_taproot.mast import TapTree, _branch_hash


def test_single_leaf_root_is_leaf_hash():
    tree = TapTree()
    tree.add_leaf(b"script-a")
    assert tree.merkle_root() == tree.leaves[0].leaf_hash()


def test_two_leaf_root_matches_manual_branch():
    tree = TapTree()
    tree.add_leaf(b"script-a")
    tree.add_leaf(b"script-b")
    h0 = tree.leaves[0].leaf_hash()
    h1 = tree.leaves[1].leaf_hash()
    assert tree.merkle_root() == _branch_hash(h0, h1)


def test_control_path_length_scales_with_depth():
    tree = TapTree()
    for i in range(4):
        tree.add_leaf(f"script-{i}".encode())
    for i in range(4):
        path = tree.control_path(i)
        assert len(path) == 2  # 4 leaves -> depth 2


def test_different_scripts_give_different_roots():
    tree_a = TapTree().add_leaf(b"script-a")
    tree_b = TapTree().add_leaf(b"script-b")
    assert tree_a.merkle_root() != tree_b.merkle_root()
