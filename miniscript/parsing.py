"""
Utilities to parse Miniscript from string and Script representations.
"""

from .fragments import (
    Just0,
    Just1,
    Pk,
    Pkh,
    Older,
    After,
    Sha256,
    Ripemd160,
    Hash256,
    Hash160,
    Multi,
    AndV,
    AndB,
    AndN,
    OrB,
    OrC,
    OrD,
    OrI,
    AndOr,
    Thresh,
    WrapA,
    WrapC,
    WrapD,
    WrapJ,
    WrapL,
    WrapN,
    WrapS,
    WrapT,
    WrapU,
    WrapV,
    Node,
)
from .key import MiniscriptKey
from .script import (
    CScriptOp,
    OP_ADD,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIGVERIFY,
    OP_EQUALVERIFY,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_FROMALTSTACK,
    OP_IFDUP,
    OP_IF,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_HASH160,
    OP_HASH256,
    OP_NOTIF,
    OP_RIPEMD160,
    OP_SHA256,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    OP_VERIFY,
    OP_0NOTEQUAL,
    ScriptNumError,
    read_script_number,
)


def stack_item_to_int(item):
    """
    Convert a stack item to an integer depending on its type.
    May raise an exception if the item is bytes, otherwise return None if it
    cannot perform the conversion.
    """
    if isinstance(item, bytes):
        return read_script_number(item)

    if isinstance(item, Node):
        if isinstance(item, Just1):
            return 1
        if isinstance(item, Just0):
            return 0

    if isinstance(item, int):
        return item

    return None


def decompose_script(script):
    """Create a list of Script element from a CScript, decomposing the compact
    -VERIFY opcodes into the non-VERIFY OP and an OP_VERIFY.
    """
    elems = []
    for elem in script:
        if elem == OP_CHECKSIGVERIFY:
            elems += [OP_CHECKSIG, OP_VERIFY]
        elif elem == OP_CHECKMULTISIGVERIFY:
            elems += [OP_CHECKMULTISIG, OP_VERIFY]
        elif elem == OP_EQUALVERIFY:
            elems += [OP_EQUAL, OP_VERIFY]
        else:
            elems.append(elem)
    return elems


def parse_term_single_elem(expr_list, idx):
    """
    Try to parse a terminal node from the element of {expr_list} at {idx}.
    """
    # Match against pk_k(key).
    if (
        isinstance(expr_list[idx], bytes)
        and len(expr_list[idx]) == 33
        and expr_list[idx][0] in [2, 3]
    ):
        expr_list[idx] = Pk(expr_list[idx])

    # Match against JUST_1 and JUST_0.
    if expr_list[idx] == 1:
        expr_list[idx] = Just1()
    if expr_list[idx] == b"":
        expr_list[idx] = Just0()


def parse_term_2_elems(expr_list, idx):
    """
    Try to parse a terminal node from two elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    elem_a = expr_list[idx]
    elem_b = expr_list[idx + 1]

    # Only older() and after() as term with 2 stack items
    if not isinstance(elem_b, CScriptOp):
        return
    try:
        n = stack_item_to_int(elem_a)
        if n is None:
            return
    except ScriptNumError:
        return

    if n <= 0 or n >= 2 ** 31:
        return

    if elem_b == OP_CHECKSEQUENCEVERIFY:
        node = Older(n)
        expr_list[idx : idx + 2] = [node]
        return expr_list

    if elem_b == OP_CHECKLOCKTIMEVERIFY:
        node = After(n)
        expr_list[idx : idx + 2] = [node]
        return expr_list


def parse_term_5_elems(expr_list, idx, pkh_preimages={}):
    """
    Try to parse a terminal node from five elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    # The only 3 items node is pk_h
    if expr_list[idx : idx + 2] != [OP_DUP, OP_HASH160]:
        return
    if not isinstance(expr_list[idx + 2], bytes):
        return
    if len(expr_list[idx + 2]) != 20:
        return
    if expr_list[idx + 3 : idx + 5] != [OP_EQUAL, OP_VERIFY]:
        return

    key_hash = expr_list[idx + 2]
    key = pkh_preimages.get(key_hash)
    assert key is not None  # TODO: have a real error here
    node = Pkh(key)
    expr_list[idx : idx + 5] = [node]
    return expr_list


def parse_term_7_elems(expr_list, idx):
    """
    Try to parse a terminal node from seven elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    # Note how all the hashes are 7 elems because the VERIFY was decomposed
    # Match against sha256.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, b"\x20", OP_EQUAL, OP_VERIFY, OP_SHA256]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 32
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Sha256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash256.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, b"\x20", OP_EQUAL, OP_VERIFY, OP_HASH256]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 32
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Hash256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against ripemd160.
    if (
        expr_list[idx : idx + 5]
        == [OP_SIZE, b"\x20", OP_EQUAL, OP_VERIFY, OP_RIPEMD160]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 20
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Ripemd160(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash160.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, b"\x20", OP_EQUAL, OP_VERIFY, OP_HASH160]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 20
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Hash160(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list


def parse_nonterm_2_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from two elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    elem_a = expr_list[idx]
    elem_b = expr_list[idx + 1]

    if isinstance(elem_a, Node):
        # Match against and_v.
        if isinstance(elem_b, Node) and elem_a.p.V and elem_b.p.has_any("BKV"):
            # Is it a special case of t: wrapper?
            if isinstance(elem_b, Just1):
                node = WrapT(elem_a)
            else:
                node = AndV(elem_a, elem_b)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against c wrapper.
        if elem_b == OP_CHECKSIG and elem_a.p.K:
            node = WrapC(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against v wrapper.
        if elem_b == OP_VERIFY and elem_a.p.B:
            node = WrapV(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against n wrapper.
        if elem_b == OP_0NOTEQUAL and elem_a.p.B:
            node = WrapN(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

    # Match against s wrapper.
    if isinstance(elem_b, Node) and elem_a == OP_SWAP and elem_b.p.has_all("Bo"):
        node = WrapS(elem_b)
        expr_list[idx : idx + 2] = [node]
        return expr_list


def parse_nonterm_3_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from *at least* three elements of
    {expr_list}, starting from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    elem_a = expr_list[idx]
    elem_b = expr_list[idx + 1]
    elem_c = expr_list[idx + 2]

    if isinstance(elem_a, Node) and isinstance(elem_b, Node):
        # Match against and_b.
        if elem_c == OP_BOOLAND and elem_a.p.B and elem_b.p.W:
            node = AndB(elem_a, elem_b)
            expr_list[idx : idx + 3] = [node]
            return expr_list

        # Match against or_b.
        if elem_c == OP_BOOLOR and elem_a.p.has_all("Bd") and elem_b.p.has_all("Wd"):
            node = OrB(elem_a, elem_b)
            expr_list[idx : idx + 3] = [node]
            return expr_list

    # Match against a wrapper.
    if (
        elem_a == OP_TOALTSTACK
        and isinstance(elem_b, Node)
        and elem_b.p.B
        and elem_c == OP_FROMALTSTACK
    ):
        node = WrapA(elem_b)
        expr_list[idx : idx + 3] = [node]
        return expr_list

    # FIXME: multi is a terminal!
    # Match against a multi.
    try:
        k = stack_item_to_int(expr_list[idx])
    except ScriptNumError:
        return
    if k is None:
        return
    # <k> (<key>)* <m> CHECKMULTISIG
    if k > len(expr_list[idx + 1 :]) - 2:
        return
    # Get the keys
    keys = []
    i = idx + 1
    while idx < len(expr_list) - 2:
        if not isinstance(expr_list[i], Pk):
            break
        keys.append(expr_list[i].pubkey)
        i += 1
    if expr_list[i + 1] == OP_CHECKMULTISIG:
        if k > len(keys):
            return
        try:
            m = stack_item_to_int(expr_list[i])
        except ScriptNumError:
            return
        if m is None or m != len(keys):
            return
        node = Multi(k, keys)
        expr_list[idx : i + 2] = [node]
        return expr_list


def parse_nonterm_4_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from at least four elements of {expr_list},
    starting from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    (it_a, it_b, it_c, it_d) = expr_list[idx : idx + 4]

    # Match against thresh. It's of the form [X] ([X] ADD)* k EQUAL
    if isinstance(it_a, Node) and it_a.p.has_all("Bdu"):
        subs = [it_a]
        # The first matches, now do all the ([X] ADD)s and return
        # if a pair is of the form (k, EQUAL).
        for i in range(idx + 1, len(expr_list) - 1, 2):
            if (
                isinstance(expr_list[i], Node)
                and expr_list[i].p.has_all("Wdu")
                and expr_list[i + 1] == OP_ADD
            ):
                subs.append(expr_list[i])
                continue
            elif expr_list[i + 1] == OP_EQUAL:
                try:
                    k = stack_item_to_int(expr_list[i])
                    if len(subs) >= k >= 1:
                        node = Thresh(k, subs)
                        expr_list[idx : i + 1 + 1] = [node]
                        return expr_list
                except ScriptNumError:
                    break
            else:
                break

    # Match against or_c.
    if (
        isinstance(it_a, Node)
        and it_a.p.has_all("Bdu")
        and it_b == OP_NOTIF
        and isinstance(it_c, Node)
        and it_c.p.V
        and it_d == OP_ENDIF
    ):
        node = OrC(it_a, it_c)
        expr_list[idx : idx + 4] = [node]
        return expr_list

    # Match against d wrapper.
    if (
        [it_a, it_b] == [OP_DUP, OP_IF]
        and isinstance(it_c, Node)
        and it_c.p.has_all("Vz")
        and it_d == OP_ENDIF
    ):
        node = WrapD(it_c)
        expr_list[idx : idx + 4] = [node]
        return expr_list


def parse_nonterm_5_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from five elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    (it_a, it_b, it_c, it_d, it_e) = expr_list[idx : idx + 5]

    # Match against or_d.
    if (
        isinstance(it_a, Node)
        and it_a.p.has_all("Bdu")
        and [it_b, it_c] == [OP_IFDUP, OP_NOTIF]
        and isinstance(it_d, Node)
        and it_d.p.B
        and it_e == OP_ENDIF
    ):
        node = OrD(it_a, it_d)
        expr_list[idx : idx + 5] = [node]
        return expr_list

    # Match against or_i.
    if (
        it_a == OP_IF
        and isinstance(it_b, Node)
        and it_b.p.has_any("BKV")
        and it_c == OP_ELSE
        and isinstance(it_d, Node)
        and it_d.p.has_any("BKV")
        and it_e == OP_ENDIF
    ):
        if isinstance(it_b, Just0):
            node = WrapL(it_d)
        elif isinstance(it_d, Just0):
            node = WrapU(it_b)
        else:
            node = OrI(it_b, it_d)
        expr_list[idx : idx + 5] = [node]
        return expr_list

    # Match against j wrapper.
    if (
        [it_a, it_b, it_c] == [OP_SIZE, OP_0NOTEQUAL, OP_IF]
        and isinstance(it_d, Node)
        and it_e == OP_ENDIF
    ):
        node = WrapJ(expr_list[idx + 3])
        expr_list[idx : idx + 5] = [node]
        return expr_list


def parse_nonterm_6_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from six elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None if there was no match.
    """
    (it_a, it_b, it_c, it_d, it_e, it_f) = expr_list[idx : idx + 6]

    # Match against andor.
    if (
        isinstance(it_a, Node)
        and it_a.p.has_all("Bdu")
        and it_b == OP_NOTIF
        and isinstance(it_c, Node)
        and it_c.p.has_any("BKV")
        and it_d == OP_ELSE
        and isinstance(it_e, Node)
        and it_e.p.has_any("BKV")
        and it_f == OP_ENDIF
    ):
        if isinstance(it_c, Just0):
            node = AndN(it_a, it_e)
        else:
            node = AndOr(it_a, it_e, it_c)
        expr_list[idx : idx + 6] = [node]
        return expr_list


def parse_expr_list(expr_list):
    """Parse a node from a list of Script elements."""
    # Every recursive call must progress the AST construction,
    # until it is complete (single root node remains).
    expr_list_len = len(expr_list)

    # Root node reached.
    if expr_list_len == 1 and isinstance(expr_list[0], Node):
        return expr_list[0]

    # Step through each list index and match against templates.
    idx = expr_list_len - 1
    while idx >= 0:
        if expr_list_len - idx >= 2:
            new_expr_list = parse_nonterm_2_elems(expr_list, idx)
            if new_expr_list is not None:
                return parse_expr_list(new_expr_list)

        if expr_list_len - idx >= 3:
            new_expr_list = parse_nonterm_3_elems(expr_list, idx)
            if new_expr_list is not None:
                return parse_expr_list(new_expr_list)

        if expr_list_len - idx >= 4:
            new_expr_list = parse_nonterm_4_elems(expr_list, idx)
            if new_expr_list is not None:
                return parse_expr_list(new_expr_list)

        if expr_list_len - idx >= 5:
            new_expr_list = parse_nonterm_5_elems(expr_list, idx)
            if new_expr_list is not None:
                return parse_expr_list(new_expr_list)

        if expr_list_len - idx >= 6:
            new_expr_list = parse_nonterm_6_elems(expr_list, idx)
            if new_expr_list is not None:
                return parse_expr_list(new_expr_list)

        # Right-to-left parsing.
        # Step one position left.
        idx -= 1

    # No match found.
    raise Exception("Malformed miniscript")


def miniscript_from_script(script, pkh_preimages={}):
    """Construct miniscript node from script.

    :param script: The Bitcoin Script to decode.
    :param pkh_preimage: A mapping from keyhash to key to decode pk_h() fragments.
    """
    expr_list = decompose_script(script)
    expr_list_len = len(expr_list)

    # We first parse terminal expressions.
    idx = 0
    while idx < expr_list_len:
        parse_term_single_elem(expr_list, idx)

        if expr_list_len - idx >= 2:
            new_expr_list = parse_term_2_elems(expr_list, idx)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        if expr_list_len - idx >= 5:
            new_expr_list = parse_term_5_elems(expr_list, idx, pkh_preimages)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        if expr_list_len - idx >= 7:
            new_expr_list = parse_term_7_elems(expr_list, idx)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        idx += 1

    # And then recursively parse non-terminal ones.
    return parse_expr_list(expr_list)


def split_params(string):
    """Read a list of values before the next ')'. Split the result by comma."""
    i = string.find(")")
    assert i >= 0

    params, remaining = string[:i], string[i:]
    if len(remaining) > 0:
        return params.split(","), remaining[1:]
    else:
        return params.split(","), ""


def parse_many(string):
    """Read a list of nodes before the next ')'."""
    subs = []
    remaining = string
    while True:
        sub, remaining = parse_one(remaining)
        subs.append(sub)
        if remaining[0] == ")":
            return subs, remaining[1:]
        assert remaining[0] == ","  # TODO: real errors
        remaining = remaining[1:]


def parse_one_num(string):
    """Read an integer before the next comma."""
    i = string.find(",")
    assert i >= 0

    return int(string[:i]), string[i + 1 :]


def parse_one(string):
    """Read a node and its subs recursively from a string.
    Returns the node and the part of the string not consumed.
    """

    # We special case Just1 and Just0 since they are the only one which don't
    # have a function syntax.
    if string[0] == "0":
        return Just0(), string[1:]
    if string[0] == "1":
        return Just1(), string[1:]

    # Now, find the separator for all functions.
    for i, char in enumerate(string):
        if char in ["(", ":"]:
            break
    # For wrappers, we may have many of them.
    if char == ":" and i > 1:
        tag, remaining = string[0], string[1:]
    else:
        tag, remaining = string[:i], string[i + 1 :]

    # Wrappers
    if char == ":":
        sub, remaining = parse_one(remaining)
        if tag == "a":
            return WrapA(sub), remaining

        if tag == "s":
            return WrapS(sub), remaining

        if tag == "c":
            return WrapC(sub), remaining

        if tag == "t":
            return WrapT(sub), remaining

        if tag == "d":
            return WrapD(sub), remaining

        if tag == "v":
            return WrapV(sub), remaining

        if tag == "j":
            return WrapJ(sub), remaining

        if tag == "n":
            return WrapN(sub), remaining

        if tag == "l":
            return WrapL(sub), remaining

        if tag == "u":
            return WrapU(sub), remaining

        assert False, (tag, sub, remaining)  # TODO: real errors

    # Terminal elements other than 0 and 1
    if tag in [
        "pk",
        "pkh",
        "pk_k",
        "pk_h",
        "sha256",
        "hash256",
        "ripemd160",
        "hash160",
        "older",
        "after",
        "multi",
    ]:
        params, remaining = split_params(remaining)

        if tag == "0":
            return Just0(), remaining

        if tag == "1":
            return Just1(), remaining

        if tag == "pk":
            return WrapC(Pk(params[0])), remaining

        if tag == "pk_k":
            return Pk(params[0]), remaining

        if tag == "pkh":
            keyhash = bytes.fromhex(params[0])
            return WrapC(Pkh(keyhash)), remaining

        if tag == "pk_h":
            keyhash_b = bytes.fromhex(params[0])
            return Pkh(keyhash_b), remaining

        if tag == "older":
            value = int(params[0])
            return Older(value), remaining

        if tag == "after":
            value = int(params[0])
            return After(value), remaining

        if tag in ["sha256", "hash256", "ripemd160", "hash160"]:
            digest = bytes.fromhex(params[0])
            if tag == "sha256":
                return Sha256(digest), remaining
            if tag == "hash256":
                return Hash256(digest), remaining
            if tag == "ripemd160":
                return Ripemd160(digest), remaining
            return Hash160(digest), remaining

        if tag == "multi":
            k = int(params.pop(0))
            key_n = []
            for param in params:
                key_obj = MiniscriptKey(param)
                key_n.append(key_obj)
            return Multi(k, key_n), remaining

        assert False, (tag, params, remaining)

    # Non-terminal elements (connectives)
    # We special case Thresh, as its first sub is an integer.
    if tag == "thresh":
        k, remaining = parse_one_num(remaining)
    # TODO: real errors in place of unpacking
    subs, remaining = parse_many(remaining)

    if tag == "and_v":
        return AndV(*subs), remaining

    if tag == "and_b":
        return AndB(*subs), remaining

    if tag == "and_n":
        return AndN(*subs), remaining

    if tag == "or_b":
        return OrB(*subs), remaining

    if tag == "or_c":
        return OrC(*subs), remaining

    if tag == "or_d":
        return OrD(*subs), remaining

    if tag == "or_i":
        return OrI(*subs), remaining

    if tag == "andor":
        return AndOr(*subs), remaining

    if tag == "thresh":
        return Thresh(k, subs), remaining

    assert False, (tag, subs, remaining)  # TODO


def miniscript_from_str(ms_str):
    """Construct miniscript node from string representation"""
    node, remaining = parse_one(ms_str)
    assert remaining == ""
    return node
