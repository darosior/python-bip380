import bip380.descriptors as descriptors

from bip380.descriptors.checksum import descsum_check
from bip380.key import DescriptorKey, DescriptorKeyError
from bip380.miniscript import Node
from bip380.miniscript.parsing import parse_one

from .errors import DescriptorParsingError
from .utils import TreeNode


def split_checksum(desc_str, strict=False):
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


def parse_tree_inner(tree_str):
    """Recursively called function to parse a tree exp. Returns a tuple (res, remaining) where
    res is the expression that was parsed (may be a Taproot tree node or a Miniscript) and remaining
    what's left to parse as a string.
    """
    if len(tree_str) == 0:
        raise DescriptorParsingError("Invalid Taproot tree expression")
    # (From BIP386)
    # A Tree Expression is:
    # - Any Script Expression that is allowed at the level this Tree Expression is in.
    # - A pair of Tree Expressions consisting of:
    #   - An open brace {
    #   - A Tree Expression
    #   - A comma ,
    #   - A Tree Expression
    #   - A closing brace }
    if tree_str[0] != "{":
        return parse_one(tree_str, is_taproot=True)
    if len(tree_str) < 5 or tree_str[-1] != "}":
        raise DescriptorParsingError("Invalid Taproot tree expression")
    left_child, remaining = parse_tree_inner(tree_str[1:])
    right_child, remaining = parse_tree_inner(remaining[1:])
    return TreeNode(left_child, right_child), remaining[1:]


def parse_tree_exp(tree_str):
    """Parse a tree expression as defined in BIP386."""
    tree, remaining = parse_tree_inner(tree_str)
    assert len(remaining) == 0, remaining
    return tree


def descriptor_from_str(desc_str, strict=False):
    """Parse a Bitcoin Output Script Descriptor from its string representation.

    :param strict: whether to require the presence of a checksum.
    """
    desc_str = split_checksum(desc_str, strict=strict)

    if desc_str.startswith("wsh(") and desc_str.endswith(")"):
        # TODO: decent errors in the Miniscript module to be able to catch them here.
        ms = Node.from_str(desc_str[4:-1], is_taproot=False)
        return descriptors.WshDescriptor(ms)

    if desc_str.startswith("wpkh(") and desc_str.endswith(")"):
        try:
            pubkey = DescriptorKey(desc_str[5:-1])
        except DescriptorKeyError as e:
            raise DescriptorParsingError(str(e))
        return descriptors.WpkhDescriptor(pubkey)

    if desc_str.startswith("tr(") and desc_str.endswith(")"):
        # First parse the key expression
        try:
            comma_index = desc_str.find(",")
            if comma_index == -1:
                pubkey = DescriptorKey(desc_str[3:-1], x_only=True)
            else:
                pubkey = DescriptorKey(desc_str[3:comma_index], x_only=True)
        except DescriptorKeyError as e:
            raise DescriptorParsingError(str(e))

        # Then the tree expression if it exists.
        tree = None
        if comma_index != -1:
            try:
                tree = parse_tree_exp(desc_str[comma_index + 1 : -1])
                # TODO: have proper exceptions..
            except Exception as e:
                raise DescriptorParsingError(str(e))

        return descriptors.TrDescriptor(pubkey, tree)

    raise DescriptorParsingError(f"Unknown descriptor fragment: {desc_str}")
