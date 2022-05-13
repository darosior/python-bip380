from __future__ import annotations

import bip380.descriptors as descriptors

from bip380.key import DescriptorKey, DescriptorKeyError
from bip380.miniscript import Node
from bip380.descriptors.checksum import descsum_check

from .errors import DescriptorParsingError


def split_checksum(desc_str: str, strict: bool = False) -> str:
    """Removes and check the provided checksum.
    If not told otherwise, this won't fail on a missing checksum.

    :param strict: whether to require the presence of the checksum.
    """
    desc_split = desc_str.split("#")
    if len(desc_split) != 2:
        if strict:
            raise DescriptorParsingError("Missing checksum")
        return desc_split[0]

    descriptor, checksum = desc_split
    if not descsum_check(desc_str):
        raise DescriptorParsingError(
            f"Checksum '{checksum}' is invalid for '{descriptor}'"
        )

    return descriptor


def descriptor_from_str(desc_str: str, strict: bool = False) -> descriptors.Descriptor:
    """Parse a Bitcoin Output Script Descriptor from its string representation.

    :param strict: whether to require the presence of a checksum.
    """
    desc_str = split_checksum(desc_str, strict=strict)

    if desc_str.startswith("wsh(") and desc_str.endswith(")"):
        # TODO: decent errors in the Miniscript module to be able to catch them here.
        ms = Node.from_str(desc_str[4:-1])
        return descriptors.WshDescriptor(ms)

    if desc_str.startswith("wpkh(") and desc_str.endswith(")"):
        try:
            pubkey = DescriptorKey(desc_str[5:-1])
        except DescriptorKeyError as e:
            raise DescriptorParsingError(str(e))
        return descriptors.WpkhDescriptor(pubkey)

    raise DescriptorParsingError(f"Unknown descriptor fragment: {desc_str}")
