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


# TODO: these parse_term functions don't need to return the expr_list
def parse_term_2_elems(expr_list, idx):
    """
    Try to parse a terminal node from two elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None on error.
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

    return None


def parse_term_5_elems(expr_list, idx):
    """
    Try to parse a terminal node from five elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None on error.
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

    node = Pkh(expr_list[idx + 2])
    expr_list[idx : idx + 5] = [node]
    return expr_list


def parse_term_7_elems(expr_list, idx):
    """
    Try to parse a terminal node from seven elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None on error.
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
    Return the new expression list on success, None on error.
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
    Return the new expression list on success, None on error.
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
    Return the new expression list on success, None on error.
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
    Return the new expression list on success, None on error.
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
    Return the new expression list on success, None on error.
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
    # Every recursive call must progress the AST construction,
    # until it is complete (single root node remains).
    expr_list_len = len(expr_list)

    # Root node reached.
    if expr_list_len == 1 and isinstance(expr_list[0], Node):
        return expr_list[0]

    # Step through each list index and match against templates.

    # Right - to - left parsing.
    # Note: Parsing from script is ambiguous:
    # r-to-l:
    #    and_v(vc:pk_h(KEY),c:pk_h(KEY))
    # l-to-r:
    #   c:and_v(vc:pk_h(KEY),pk_h(KEY))

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


def miniscript_from_script(script):
    """Construct miniscript node from script"""
    expr_list = decompose_script(script)
    expr_list_len = len(expr_list)

    # Parse for terminal expressions.
    idx = 0
    while idx < expr_list_len:
        parse_term_single_elem(expr_list, idx)

        if expr_list_len - idx >= 2:
            new_expr_list = parse_term_2_elems(expr_list, idx)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        if expr_list_len - idx >= 5:
            new_expr_list = parse_term_5_elems(expr_list, idx)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        if expr_list_len - idx >= 7:
            new_expr_list = parse_term_7_elems(expr_list, idx)
            if new_expr_list is not None:
                expr_list = new_expr_list
                expr_list_len = len(expr_list)

        idx += 1

    # Construct AST recursively.
    return parse_expr_list(expr_list)


def parse_string(string):
    string = "".join(string.split())  # FIXME
    tag = ""
    sub_exprs = []
    depth = 0

    for idx, ch in enumerate(string):
        if (ch == "0" or ch == "1") and len(string) == 1:
            return ch, sub_exprs
        if ch == ":" and depth == 0:
            # Discern between 1 or two wrappers. FIXME
            if idx == 1:
                return string[0], [string[2:]]
            else:
                return string[0], [string[1:]]
        if ch == "(":
            depth += 1
            if depth == 1:
                tag = string[:idx]
                prev_idx = idx
        if ch == ")":
            depth -= 1
            if depth == 0:
                sub_exprs.append(string[prev_idx + 1 : idx])
        if ch == "," and depth == 1:
            sub_exprs.append(string[prev_idx + 1 : idx])
            prev_idx = idx
    if depth == 0 and bool(tag) and bool(sub_exprs):
        return tag, sub_exprs
    else:
        raise Exception("Malformed miniscript string.")


def parse_sub_strings(sub_exprs):
    sub_nodes = []
    for string in sub_exprs:
        sub_nodes.append(miniscript_from_str(string))
    return sub_nodes


def miniscript_from_str(ms_str):
    """Construct miniscript node from string representation"""
    tag, sub_exprs = parse_string(ms_str)
    k = None

    if tag == "0":
        return Just0()

    if tag == "1":
        return Just1()

    if tag == "pk":
        return WrapC(Pk(sub_exprs[0]))

    if tag == "pk_k":
        return Pk(sub_exprs[0])

    if tag == "pkh":
        keyhash = bytes.fromhex(sub_exprs[0])
        return WrapC(Pkh(keyhash))

    if tag == "pk_h":
        keyhash_b = bytes.fromhex(sub_exprs[0])
        return Pkh(keyhash_b)

    if tag == "older":
        value = int(sub_exprs[0])
        return Older(value)

    if tag == "after":
        value = int(sub_exprs[0])
        return After(value)

    if tag in ["sha256", "hash256", "ripemd160", "hash160"]:
        digest = bytes.fromhex(sub_exprs[0])
        if tag == "sha256":
            return Sha256(digest)
        if tag == "hash256":
            return Hash256(digest)
        if tag == "ripemd160":
            return Ripemd160(digest)
        return Hash160(digest)

    if tag == "multi":
        k = int(sub_exprs.pop(0))
        key_n = []
        for sub_expr in sub_exprs:
            key_obj = MiniscriptKey(sub_expr)
            key_n.append(key_obj)
        return Multi(k, key_n)

    if tag == "and_v":
        return AndV(*parse_sub_strings(sub_exprs))

    if tag == "and_b":
        return AndB(*parse_sub_strings(sub_exprs))

    if tag == "and_n":
        return AndN(*parse_sub_strings(sub_exprs))

    if tag == "or_b":
        return OrB(*parse_sub_strings(sub_exprs))

    if tag == "or_c":
        return OrC(*parse_sub_strings(sub_exprs))

    if tag == "or_d":
        return OrD(*parse_sub_strings(sub_exprs))

    if tag == "or_i":
        return OrI(*parse_sub_strings(sub_exprs))

    if tag == "andor":
        return AndOr(*parse_sub_strings(sub_exprs))

    if tag == "thresh":
        k = int(sub_exprs.pop(0))
        return Thresh(k, parse_sub_strings(sub_exprs))

    if tag == "a":
        return WrapA(*parse_sub_strings(sub_exprs))

    if tag == "s":
        return WrapS(*parse_sub_strings(sub_exprs))

    if tag == "c":
        return WrapC(*parse_sub_strings(sub_exprs))

    if tag == "t":
        return WrapT(*parse_sub_strings(sub_exprs))

    if tag == "d":
        return WrapD(*parse_sub_strings(sub_exprs))

    if tag == "v":
        return WrapV(*parse_sub_strings(sub_exprs))

    if tag == "j":
        return WrapJ(*parse_sub_strings(sub_exprs))

    if tag == "n":
        return WrapN(*parse_sub_strings(sub_exprs))

    if tag == "l":
        return WrapL(*parse_sub_strings(sub_exprs))

    if tag == "u":
        return WrapU(*parse_sub_strings(sub_exprs))

    assert False, (tag, sub_exprs)  # TODO
