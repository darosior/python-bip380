from __future__ import annotations

from enum import Enum, auto
from typing import List, Optional, Union

from bip32 import BIP32
from bip32.utils import coincurve, _deriv_path_str_to_list

from bip380.utils.hashes import hash160


class DescriptorKeyError(Exception):
    def __init__(self, message: str):
        self.message: str = message


class DescriporKeyOrigin:
    """The origin of a key in a descriptor.

    See https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions.
    """

    def __init__(self, fingerprint: bytes, path: List[int]):
        assert isinstance(fingerprint, bytes) and isinstance(path, list)

        self.fingerprint: bytes = fingerprint
        self.path: List[int] = path

    def from_str(origin_str: str) -> DescriporKeyOrigin:
        # Origing starts and ends with brackets
        if not origin_str.startswith("[") or not origin_str.endswith("]"):
            raise DescriptorKeyError(f"Insane origin: '{origin_str}'")
        # At least 8 hex characters + brackets
        if len(origin_str) < 10:
            raise DescriptorKeyError(f"Insane origin: '{origin_str}'")

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


class KeyPathKind(Enum):
    FINAL = auto()
    WILDCARD_UNHARDENED = auto()
    WILDCARD_HARDENED = auto()

    def is_wildcard(self) -> bool:
        return self in [KeyPathKind.WILDCARD_HARDENED, KeyPathKind.WILDCARD_UNHARDENED]


class DescriptorKeyPath:
    """The derivation path of a key in a descriptor.

    See https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions.
    """

    def __init__(self, path: List[int], kind: KeyPathKind):
        assert isinstance(path, list) and isinstance(kind, KeyPathKind)

        self.path: List[int] = path
        self.kind: KeyPathKind = kind

    def from_str(path_str: str) -> DescriptorKeyPath:
        if len(path_str) < 1:
            raise DescriptorKeyError(f"Insane key path: '{path_str}'")
        if path_str[0] == "/":
            raise DescriptorKeyError(f"Insane key path: '{path_str}'")

        # Determine whether this key may be derived.
        kind = KeyPathKind.FINAL
        if path_str[-2:] in ["*'", "*h", "*H"]:
            kind = KeyPathKind.WILDCARD_HARDENED
            path_str = path_str[:-2]
        elif path_str[-1] == "*":
            kind = KeyPathKind.WILDCARD_UNHARDENED
            path_str = path_str[:-1]

        # We use an internal helper from python-bip32 to parse the path.
        # The helper operates on "m/10h/11/12'/13", so give it a "m/".
        if len(path_str) > 1:
            dummy = "m/"
            # If we just trimmed the wildcard part, time the trailing '/' too.
            if kind.is_wildcard():
                path_str = path_str[:-1]
            try:
                path = _deriv_path_str_to_list(dummy + path_str)
            except ValueError:
                raise DescriptorKeyError(f"Insane path in key path: '{path_str}'")
        else:
            path = []

        return DescriptorKeyPath(path, kind)


class DescriptorKey:
    """A Bitcoin key to be used in Output Script Descriptors.

    May be an extended or raw public key.
    """

    origin: Optional[DescriporKeyOrigin]
    path: Optional[DescriptorKeyPath]
    key: Union[coincurve.PublicKey, BIP32]

    def __init__(self, key: Union[bytes, BIP32, str]):
        # Information about the origin of this key.
        self.origin = None
        # If it is an xpub, a path toward a child key of that xpub.
        self.path = None

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
            # Try parsing an optional origin prepended to the key
            splitted_key = key.split("]", maxsplit=1)
            if len(splitted_key) == 2:
                origin, key = splitted_key
                self.origin = DescriporKeyOrigin.from_str(origin + "]")

            # Is it a raw key?
            if len(key) == 66:
                try:
                    self.key = coincurve.PublicKey(bytes.fromhex(key))
                except ValueError as e:
                    raise DescriptorKeyError(f"Public key parsing error: '{str(e)}'")
            # If not it must be an xpub.
            else:
                # There may be an optional path appended to the xpub.
                splitted_key = key.split("/", maxsplit=1)
                if len(splitted_key) == 2:
                    key, path = splitted_key
                    self.path = DescriptorKeyPath.from_str(path)

                try:
                    self.key = BIP32.from_xpub(key)
                except ValueError as e:
                    raise DescriptorKeyError(f"Xpub parsing error: '{str(e)}'")

        else:
            raise DescriptorKeyError(
                "Invalid parameter type: expecting bytes, hex str or BIP32 instance."
            )

    def __repr__(self) -> str:
        key = ""

        def ser_path(key: str, path: List[int]) -> str:
            for i in path:
                if i < 2**31:
                    key += f"/{i}"
                else:
                    key += f"/{i - 2**31}'"
            return key

        if self.origin is not None:
            key += f"[{self.origin.fingerprint.hex()}"
            key = ser_path(key, self.origin.path)
            key += "]"

        if isinstance(self.key, BIP32):
            key += self.key.get_xpub()
        else:
            assert isinstance(self.key, coincurve.PublicKey)
            key += self.key.format().hex()

        if self.path is not None:
            key = ser_path(key, self.path.path)
            if self.path.kind.is_wildcard():
                key += "/*"

        return key

    def bytes(self) -> bytes:
        if isinstance(self.key, coincurve.PublicKey):
            return self.key.format()
        else:
            assert isinstance(self.key, BIP32)
            if self.path is None or self.path.path == []:
                return self.key.pubkey
            assert not self.path.kind.is_wildcard()  # TODO: real errors
            return self.key.get_pubkey_from_path(self.path.path)

    def derive(self, index: int) -> None:
        """Derive the key at the given index.

        A no-op if the key isn't a wildcard. Will start from 2**31 if the key is a "hardened
        wildcard".
        """
        assert isinstance(index, int)
        if self.path is None or self.path.kind == KeyPathKind.FINAL:
            return
        assert isinstance(self.key, BIP32)

        if self.path.kind == KeyPathKind.WILDCARD_HARDENED:
            index += 2 ** 31
        assert index <= 2 ** 32

        if self.origin is None:
            fingerprint = hash160(self.key.pubkey)[:4]
            self.origin = DescriporKeyOrigin(fingerprint, [index])
        else:
            self.origin.path.append(index)
        # TODO(bip32): have a way to derive without roundtripping through string ser.
        self.key = BIP32.from_xpub(
            self.key.get_xpub_from_path(self.path.path + [index])
        )
        self.path = None
