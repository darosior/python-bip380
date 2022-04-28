from bip380.key import DescriptorKey
from bip380.miniscript import Node
from bip380.utils.hashes import sha256, hash160
from bip380.utils.script import (
    CScript,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
)

from .checksum import descsum_create
from .parsing import descriptor_from_str


class Descriptor:
    """A Bitcoin Output Script Descriptor."""

    def from_str(desc_str, strict=False):
        """Parse a Bitcoin Output Script Descriptor from its string representation.

        :param strict: whether to require the presence of a checksum.
        """
        return descriptor_from_str(desc_str, strict)

    @property
    def script_pubkey(self):
        """Get the ScriptPubKey (output 'locking' Script) for this descriptor."""
        # To be implemented by derived classes
        raise NotImplementedError

    @property
    def script_sighash(self):
        """Get the Script to be committed to by the signature hash of a spending transaction."""
        # To be implemented by derived classes
        raise NotImplementedError

    @property
    def keys(self):
        """Get the list of all keys from this descriptor, in order of apparition."""
        # To be implemented by derived classes
        raise NotImplementedError

    def derive(self, index):
        """Derive the key at the given derivation index.

        A no-op if the key isn't a wildcard. Will start from 2**31 if the key is a "hardened
        wildcard".
        """
        assert isinstance(index, int)
        for key in self.keys:
            key.derive(index)

    def satisfy(self, *args, **kwargs):
        """Get the witness stack to spend from this descriptor.

        Various data may need to be passed as parameters to meet the locking
        conditions set by the Script.
        """
        # To be implemented by derived classes
        raise NotImplementedError


# TODO: add methods to give access to all the Miniscript analysis
class WshDescriptor(Descriptor):
    """A Segwit v0 P2WSH Output Script Descriptor."""

    def __init__(self, witness_script):
        assert isinstance(witness_script, Node)
        self.witness_script = witness_script

    def __repr__(self):
        return descsum_create(f"wsh({self.witness_script})")

    @property
    def script_pubkey(self):
        witness_program = sha256(self.witness_script.script)
        return CScript([0, witness_program])

    @property
    def script_sighash(self):
        return self.witness_script.script

    @property
    def keys(self):
        return self.witness_script.keys

    def satisfy(self, sat_material=None):
        """Get the witness stack to spend from this descriptor.

        :param sat_material: a miniscript.satisfaction.SatisfactionMaterial with data
                             available to fulfill the conditions set by the Script.
        """
        sat = self.witness_script.satisfy(sat_material)
        if sat is not None:
            return sat + [self.witness_script.script]


class WpkhDescriptor(Descriptor):
    """A Segwit v0 P2WPKH Output Script Descriptor."""

    def __init__(self, pubkey):
        assert isinstance(pubkey, DescriptorKey)
        self.pubkey = pubkey

    def __repr__(self):
        return descsum_create(f"wpkh({self.pubkey})")

    @property
    def script_pubkey(self):
        witness_program = hash160(self.pubkey.bytes())
        return CScript([0, witness_program])

    @property
    def script_sighash(self):
        key_hash = hash160(self.pubkey.bytes())
        return CScript([OP_DUP, OP_HASH160, key_hash, OP_EQUALVERIFY, OP_CHECKSIG])

    @property
    def keys(self):
        return [self.pubkey]

    def satisfy(self, signature):
        """Get the witness stack to spend from this descriptor.

        :param signature: a signature (in bytes) for the pubkey from the descriptor.
        """
        assert isinstance(signature, bytes)
        return [signature, self.pubkey.bytes()]
