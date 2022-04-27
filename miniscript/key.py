from bip32 import BIP32
from bip32.utils import coincurve


class DescriptorKeyError(Exception):
    def __init__(self, message):
        self.message = message


class DescriptorKey:
    """A Bitcoin key to be used in Output Script Descriptors.

    May be an extended or raw public key.
    """

    def __init__(self, key):
        if isinstance(key, bytes):
            if len(key) != 33:
                raise DescriptorKeyError("Only compressed keys are supported")
            try:
                self.key = coincurve.PublicKey(key)
            except ValueError as e:
                raise DescriptorKeyError(f"Public key parsing error: '{str(e)}'")

        elif isinstance(key, BIP32):
            self.key = key

        elif isinstance(key, str):
            if len(key) == 66:
                try:
                    self.key = coincurve.PublicKey(bytes.fromhex(key))
                except ValueError as e:
                    raise DescriptorKeyError(f"Public key parsing error: '{str(e)}'")
            else:
                try:
                    self.key = BIP32.from_xpub(key)
                except ValueError as e:
                    raise DescriptorKeyError(f"Xpub parsing error: '{str(e)}'")

        else:
            raise DescriptorKeyError(
                "Invalid parameter type: expecting bytes, hex str or BIP32 instance."
            )

    def bytes(self):
        if isinstance(self.key, coincurve.PublicKey):
            return self.key.format()
        else:
            assert isinstance(self.key, BIP32)
            return self.key.get_pubkey_from_path("m")
