"""Utilities for working with descriptors."""

import coincurve
import hashlib

from bip380.miniscript import Node
from bip380.utils.script import CScript


def compact_size(byte_arr):
    """The size prefix for this byte array encoded as little-endian.

    See https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer.
    """
    size = len(byte_arr)
    if size < 253:
        return size.to_bytes(1, "little")
    if size < 2**16:
        return b"\xfd" + size.to_bytes(2, "little")
    if size < 2**32:
        return b"\xfe" + size.to_bytes(4, "little")
    return b"\xff" + size.to_bytes(8, "little")


def tagged_hash(tag, data):
    ss = hashlib.sha256(tag.encode("utf-8")).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


def tapleaf_hash(leaf):
    """Compute the hash of a Taproot leaf as defined in BIP341."""
    assert isinstance(leaf, CScript)
    script = bytes(leaf)
    return tagged_hash("TapLeaf", b"\xc0" + compact_size(script) + script)


def tapbranch_hash(left_hash, right_hash):
    """Compute the Taproot branch hash for left and right child hashes.
    This takes care of the sorting as per BIP341.
    """
    assert all(isinstance(h, bytes) for h in (left_hash, right_hash))
    if right_hash < left_hash:
        return tagged_hash("TapBranch", right_hash + left_hash)
    return tagged_hash("TapBranch", left_hash + right_hash)


def taproot_tweak(pubkey_bytes, merkle_root):
    """Compute the tweak to get the output key of a Taproot, as per BIP341."""
    assert isinstance(pubkey_bytes, bytes) and len(pubkey_bytes) == 32
    assert isinstance(merkle_root, bytes)

    t = tagged_hash("TapTweak", pubkey_bytes + merkle_root)
    xonly_pubkey = coincurve.PublicKeyXOnly(pubkey_bytes)
    xonly_pubkey.tweak_add(t)  # TODO: error handling

    return xonly_pubkey


class TreeNode:
    """A node in a Taproot tree"""

    def __init__(self, left_child, right_child):
        """Instanciate a Taproot tree node with its two child. Each may be a leaf node."""
        assert all(isinstance(c, (TreeNode, Node)) for c in (left_child, right_child))
        self.left_child = left_child
        self.right_child = right_child

        # Cached merkle root of the tree as per BIP341
        self._merkle_root = None

    def __repr__(self):
        return f"{{{self.left_child},{self.right_child}}}"

    def _compute_merkle_proofs(self, merkle_proof=[]):
        """Internal method to compute the leaf-to-merkle-proof mapping."""
        if isinstance(self.left_child, Node) and isinstance(self.right_child, Node):
            return {
                self.left_child: [tapleaf_hash(self.right_child.script)] + merkle_proof,
                self.right_child: [tapleaf_hash(self.left_child.script)] + merkle_proof,
            }
        if isinstance(self.left_child, Node):
            return {
                self.left_child: [self.right_child.merkle_root()] + merkle_proof,
                **self.right_child._compute_merkle_proofs(
                    [tapleaf_hash(self.left_child.script)] + merkle_proof
                ),
            }
        if isinstance(self.right_child, Node):
            return {
                self.right_child: [self.left_child.merkle_root()] + merkle_proof,
                **self.left_child._compute_merkle_proofs(
                    [tapleaf_hash(self.right_child.script)] + merkle_proof
                ),
            }
        return {
            **self.left_child._compute_merkle_proofs(
                [self.right_child.merkle_root()] + merkle_proof
            ),
            **self.right_child._compute_merkle_proofs(
                [self.left_child.merkle_root()] + merkle_proof
            ),
        }

    def merkle_proofs(self):
        """Get a mapping from each leaf to its merkle proof."""
        return self._compute_merkle_proofs()

    def leaves(self):
        """Get the list of all the leaves."""
        if isinstance(self.left_child, Node) and isinstance(self.right_child, Node):
            return [self.left_child, self.right_child]
        if isinstance(self.left_child, Node):
            return [self.left_child] + self.right_child.leaves()
        if isinstance(self.right_child, Node):
            return self.left_child.leaves() + [self.right_child]
        return self.left_child.leaves() + self.right_child.leaves()

    def _child_hash(self, child):
        """The hash of a child depending on whether it's a leaf or not."""
        if isinstance(child, Node):
            return tapleaf_hash(child.script)
        assert isinstance(child, TreeNode)
        return child.merkle_root()

    def _compute_merkle_root(self):
        left_hash = self._child_hash(self.left_child)
        right_hash = self._child_hash(self.right_child)
        return tapbranch_hash(left_hash, right_hash)

    def merkle_root(self):
        if self._merkle_root is None:
            self._merkle_root = self._compute_merkle_root()
        return self._merkle_root


class TaplefSat:
    """A satisfaction for a Taptree leaf."""

    def __init__(self, merkle_proof, script_sat, script):
        assert isinstance(merkle_proof, list)
        assert isinstance(script_sat, list)
        assert isinstance(script, CScript)

        # The merkle proof to the leaf
        self.merkle_proof = merkle_proof
        # The depth of the leaf in the tree. Used to compute the cost of the whole
        # satisfaction.
        self.depth = len(merkle_proof)
        # The script represented by this leaf
        self.script = script
        self.script_len = len(bytes(script))
        # The witness for satisfying this script
        self.script_sat = script_sat
        self.sat_size = sum(len(elem) for elem in script_sat)

    def __lt__(self, other):
        """Whether this satisfaction is smaller (ie less expensive) than the other one."""
        return (self.depth + self.sat_size + self.script_len) < (
            other.depth + other.sat_size + other.script_len
        )

    def witness(self, internal_key, output_key_parity):
        """Get the full witness for satisfying this leaf."""
        control_block = (
            bytes([0xC0 | output_key_parity])
            + internal_key.bytes()
            + b"".join(self.merkle_proof)
        )
        return self.script_sat + [bytes(self.script), control_block]
