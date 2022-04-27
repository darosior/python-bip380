import hashlib

from miniscript.miniscript.key import MiniscriptKey
from miniscript.miniscript.fragments import Node, hash160
from miniscript.miniscript.script import CScript


class Descriptor:
    """A Bitcoin Output Script Descriptor."""

    def from_str():
        raise NotImplementedError

    def from_script():
        raise NotImplementedError

    def script_pubkey(self):
        """Get the ScriptPubKey (output 'locking' Script) for this descriptor."""
        # To be implemented by derived classes
        raise NotImplementedError

    def satisfy(self, *args, **kwargs):
        """Get the witness stack to spend from this descriptor.

        Various data may need to be passed as parameters to meet the locking
        conditions set by the Script.
        """
        # To be implemented by derived classes
        raise NotImplementedError


class WshDescriptor(Descriptor):
    """A Segwit v0 P2WSH Output Script Descriptor."""

    def __init__(self, witness_script):
        assert isinstance(witness_script, Node)
        self.witness_script = witness_script

    def __repr__(self):
        # FIXME: checksum
        return f"wsh({self.witness_script})"

    def script_pubkey(self):
        # TODO: have a utils module with hashes routines
        witness_program = hashlib.sha256(self.witness_script).digest()
        return CScript([0, witness_program])

    def satisfy(self, sat_material=None):
        """Get the witness stack to spend from this descriptor.

        :param sat_material: a miniscript.satisfaction.SatisfactionMaterial with data
                             available to fulfill the conditions set by the Script.
        """
        sat = self.witness_script.satisfy(sat_material)
        if sat is not None:
            return sat + [self.witness_script]


class WpkhDescriptor(Descriptor):
    """A Segwit v0 P2WPKH Output Script Descriptor."""

    def __init__(self, pubkey):
        assert isinstance(pubkey, MiniscriptKey)
        self.pubkey = pubkey

    def __repr__(self):
        # FIXME: checksum
        return f"wpkh({self.pubkey})"

    def script_pubkey(self):
        # TODO: have a utils module with hashes routines
        witness_program = hash160(self.pubkey.bytes())
        return CScript([0, witness_program])

    def satisfy(self, signature):
        """Get the witness stack to spend from this descriptor.

        :param signature: a signature (in bytes) for the pubkey from the descriptor.
        """
        assert isinstance(signature, bytes)
        return [signature, self.pubkey]
