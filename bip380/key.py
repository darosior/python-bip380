from bip32 import BIP32
from bip32.utils import coincurve, _deriv_path_str_to_list
from bip380.utils.hashes import hash160


class DescriptorKeyError(Exception):
    def __init__(self, message):
        self.message = message


class DescriporKeyOrigin:
    """The origin of a key in a descriptor.

    See https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions.
    """

    def __init__(self, fingerprint, path):
        assert isinstance(fingerprint, bytes) and isinstance(path, list)

        self.fingerprint = fingerprint
        self.path = path

    def from_str(origin_str):
        # Origing starts and ends with brackets
        if not origin_str.startswith("[") or not origin_str.endswith("]"):
            return None
        # At least 8 hex characters + brackets
        if len(origin_str) < 10:
            return None

        # For the fingerprint, just read the 4 bytes.
        try:
            fingerprint = bytes.fromhex(origin_str[1:9])
        except ValueError:
            raise DescriptorKeyError(f"Insane fingerprint in origin: '{origin_str}'")
        # For the path, we (how bad) reuse an internal helper from python-bip32.
        path = []
        if len(origin_str) > 10:
            if origin_str[9] != "/":
                raise DescriptorKeyError(f"Insane path in origin: '{origin_str}'")
            # The helper operates on "m/10h/11/12'/13", so give it a "m".
            dummy = "m"
            try:
                path = _deriv_path_str_to_list(dummy + origin_str[9:-1])
            except ValueError:
                raise DescriptorKeyError(f"Insane path in origin: '{origin_str}'")

        return DescriporKeyOrigin(fingerprint, path)


class DescriptorKey:
    """A Bitcoin key to be used in Output Script Descriptors.

    May be an extended or raw public key.
    """

    def __init__(self, key):
        # Information about the origin of this key.
        self.origin = None

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
            splitted_key = key.split("]", maxsplit=1)
            if len(splitted_key) > 1:
                origin, key = splitted_key
                self.origin = DescriporKeyOrigin.from_str(origin + "]")

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

    def __repr__(self):
        key = ""

        if self.origin is not None:
            key += f"[{self.origin.fingerprint.hex()}"
            for index in self.origin.path:
                key += f"/{index}"
            key += "]"

        if isinstance(self.key, BIP32):
            key += self.key.get_xpub()
        else:
            assert isinstance(self.key, coincurve.PublicKey)
            key += self.key.format().hex()

        return key

    def bytes(self):
        if isinstance(self.key, coincurve.PublicKey):
            return self.key.format()
        else:
            assert isinstance(self.key, BIP32)
            return self.key.pubkey

    def derive(self, index):
        """Derive the key at the given path. A no-op if the key isn't derive-able."""
        assert isinstance(index, int)
        if isinstance(self.key, coincurve.PublicKey):
            return
        assert isinstance(self.key, BIP32)
        print(self.key.get_xpub_from_path([index]))
        self.key = BIP32.from_xpub(self.key.get_xpub_from_path([index]))
        if self.origin is None:
            fingerprint = hash160(self.key.pubkey)[:4]
            self.origin = DescriporKeyOrigin(fingerprint, [index])
        else:
            self.origin.path.append(index)
