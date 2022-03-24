# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Classes and methods to encode and decode miniscripts"""
import hashlib

from enum import Enum

from .key import MiniscriptKey
from .property import Property
from .script import (
    CScript,
    CScriptOp,
    OP_1,
    OP_0,
    OP_ADD,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_IFDUP,
    OP_IF,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
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
    read_script_number,
    ScriptNumError,
)


def hash160(data):
    """{data} must be bytes, returns ripemd160(sha256(data))"""
    sha2 = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha2).digest()


class Fragment(Enum):
    JUST_0 = 0
    JUST_1 = 1
    PK_K = 2
    PK_H = 3
    OLDER = 4
    AFTER = 5
    SHA256 = 6
    HASH256 = 7
    RIPEMD160 = 8
    HASH160 = 9
    WRAP_A = 10
    WRAP_S = 11
    WRAP_C = 12
    WRAP_T = 13
    WRAP_D = 14
    WRAP_V = 15
    WRAP_J = 16
    WRAP_N = 17
    WRAP_U = 18
    WRAP_L = 19
    AND_V = 20
    AND_B = 21
    AND_N = 22
    OR_B = 23
    OR_C = 24
    OR_D = 25
    OR_I = 26
    ANDOR = 27
    THRESH = 28
    MULTI = 29


class MiniscriptNodeCreationError(ValueError):
    def __init__(self, message):
        self.message = message


def stack_item_to_int(item):
    """
    Convert a stack item to an integer depending on its type.
    May raise an exception if the item is bytes, otherwise return None if it
    cannot perform the conversion.
    """
    if isinstance(item, bytes):
        return read_script_number(item)

    if isinstance(item, Node):
        if item.t == Fragment.JUST_1:
            return 1
        if item.t == Fragment.JUST_0:
            return 0

    if isinstance(item, int):
        return item

    return None


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
        expr_list[idx] = PkNode(expr_list[idx])

    # Match against JUST_1 and JUST_0.
    if expr_list[idx] == 1:
        expr_list[idx] = Just1()
    if expr_list[idx] == 0:
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

    node = PkhNode(expr_list[idx + 2])
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
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_SHA256]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 32
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Sha256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash256.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_HASH256]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 32
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Hash256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against ripemd160.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_RIPEMD160]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 20
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Ripemd160(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash160.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_HASH160]
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
            if elem_b.t == Fragment.JUST_1:
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
        if not isinstance(expr_list[i], PkNode):
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

    # Match against l wrapper.
    if (
        it_a == OP_IF
        and isinstance(it_b, Node)
        and it_b.t == Fragment.JUST_0
        and it_c == OP_ELSE
        and isinstance(it_d, Node)
        and it_d.p.has_any("BKV")
        and it_e == OP_ENDIF
    ):
        node = WrapL(it_d)
        expr_list[idx : idx + 5] = [node]
        return expr_list

    # Match against u wrapper.
    if (
        it_a == OP_IF
        and isinstance(it_b, Node)
        and it_b.p.has_any("BKV")
        and [it_c, it_d, it_e] == [OP_ELSE, 0, OP_ENDIF]
    ):
        node = WrapU(it_b)
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


class Node:
    """Miniscript expression class

    Provides methods to instantiate a miniscript node from a string descriptor
    or script.
    """

    def __init__(self):
        # TODO: rename (or remove..)
        self.desc = ""
        self.children = None
        self.t = None
        self.p = None
        self._k = None
        self._pk_k = []
        self._pk_h = []
        # A list of Script elements, a CScript is created all at once in the script() method.
        self._script = []

    def __repr__(self):
        return f"{self.t}(k = {self._k}, pk_k = {[k.hex() for k in self._pk_k]}, pk_h = {self._pk_h})"

    # TODO: rename..
    @staticmethod
    def from_desc(string):
        """Construct miniscript node from string descriptor"""
        tag, child_exprs = Node._parse_string(string)
        k = None

        if tag == "0":
            return Just0()

        if tag == "1":
            return Just1()

        if tag == "pk":
            return WrapC(PkNode(child_exprs[0]))

        if tag == "pk_k":
            return PkNode(child_exprs[0])

        if tag == "pkh":
            keyhash = bytes.fromhex(child_exprs[0])
            return WrapC(PkhNode(keyhash))

        if tag == "pk_h":
            keyhash_b = bytes.fromhex(child_exprs[0])
            return PkhNode(keyhash_b)

        if tag == "older":
            n = int(child_exprs[0])
            return Older(n)

        if tag == "after":
            # FIXME: rename
            time = int(child_exprs[0])
            return After(time)

        if tag in ["sha256", "hash256", "ripemd160", "hash160"]:
            digest = bytes.fromhex(child_exprs[0])
            if tag == "sha256":
                return Sha256(digest)
            if tag == "hash256":
                return Hash256(digest)
            if tag == "ripemd160":
                return Ripemd160(digest)
            return Hash160(digest)

        if tag == "multi":
            k = int(child_exprs.pop(0))
            key_n = []
            for child_expr in child_exprs:
                key_obj = MiniscriptKey(child_expr)
                key_n.append(key_obj)
            return Multi(k, key_n)

        if tag == "and_v":
            return AndV(*Node._parse_child_strings(child_exprs))

        if tag == "and_b":
            return AndB(*Node._parse_child_strings(child_exprs))

        if tag == "and_n":
            return AndN(*Node._parse_child_strings(child_exprs))

        if tag == "or_b":
            return OrB(*Node._parse_child_strings(child_exprs))

        if tag == "or_c":
            return OrC(*Node._parse_child_strings(child_exprs))

        if tag == "or_d":
            return OrD(*Node._parse_child_strings(child_exprs))

        if tag == "or_i":
            return OrI(*Node._parse_child_strings(child_exprs))

        if tag == "andor":
            return AndOr(*Node._parse_child_strings(child_exprs))

        if tag == "thresh":
            k = int(child_exprs.pop(0))
            return Thresh(k, Node._parse_child_strings(child_exprs))

        if tag == "a":
            return WrapA(*Node._parse_child_strings(child_exprs))

        if tag == "s":
            return WrapS(*Node._parse_child_strings(child_exprs))

        if tag == "c":
            return WrapC(*Node._parse_child_strings(child_exprs))

        if tag == "t":
            return WrapT(*Node._parse_child_strings(child_exprs))

        if tag == "d":
            return WrapD(*Node._parse_child_strings(child_exprs))

        if tag == "v":
            return WrapV(*Node._parse_child_strings(child_exprs))

        if tag == "j":
            return WrapJ(*Node._parse_child_strings(child_exprs))

        if tag == "n":
            return WrapN(*Node._parse_child_strings(child_exprs))

        if tag == "l":
            return WrapL(*Node._parse_child_strings(child_exprs))

        if tag == "u":
            return WrapU(*Node._parse_child_strings(child_exprs))

        assert False  # TODO

    # TODO: have something like BuildScript from Core and get rid of the _script member.
    @property
    def script(self):
        return CScript(self._script)

    @staticmethod
    def from_script(c_script):
        """Construct miniscript node from script"""
        # FIXME: avoid looping 45678 times ..
        expr_list = []
        for op in c_script:
            # Encode 0, 20, 32 as int.
            if op in [b"", b"\x14", b"\x20"]:
                op_int = int.from_bytes(op, byteorder="big")
                expr_list.append(op_int)
            else:
                expr_list.append(op)

        # Decompose script:
        # OP_CHECKSIGVERIFY > OP_CHECKSIG + OP_VERIFY
        # OP_CHECKMULTISIGVERIFY > OP_CHECKMULTISIG + OP_VERIFY
        # OP_EQUALVERIFY > OP_EQUAL + OP_VERIFY
        expr_list = Node._decompose_script(expr_list)
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
        return Node._parse_expr_list(expr_list)

    @staticmethod
    def _parse_expr_list(expr_list):
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
                    return Node._parse_expr_list(new_expr_list)

            if expr_list_len - idx >= 3:
                new_expr_list = parse_nonterm_3_elems(expr_list, idx)
                if new_expr_list is not None:
                    return Node._parse_expr_list(new_expr_list)

            if expr_list_len - idx >= 4:
                new_expr_list = parse_nonterm_4_elems(expr_list, idx)
                if new_expr_list is not None:
                    return Node._parse_expr_list(new_expr_list)

            if expr_list_len - idx >= 5:
                new_expr_list = parse_nonterm_5_elems(expr_list, idx)
                if new_expr_list is not None:
                    return Node._parse_expr_list(new_expr_list)

            if expr_list_len - idx >= 6:
                new_expr_list = parse_nonterm_6_elems(expr_list, idx)
                if new_expr_list is not None:
                    return Node._parse_expr_list(new_expr_list)

            # Right-to-left parsing.
            # Step one position left.
            idx -= 1

        # No match found.
        raise Exception("Malformed miniscript")

    @staticmethod
    def _parse_child_strings(child_exprs):
        child_nodes = []
        for string in child_exprs:
            child_nodes.append(Node.from_desc(string))
        return child_nodes

    @staticmethod
    def _parse_string(string):
        string = "".join(string.split())
        tag = ""
        child_exprs = []
        depth = 0

        for idx, ch in enumerate(string):
            if (ch == "0" or ch == "1") and len(string) == 1:
                return ch, child_exprs
            if ch == ":" and depth == 0:
                # Discern between 1 or two wrappers.
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
                    child_exprs.append(string[prev_idx + 1 : idx])
            if ch == "," and depth == 1:
                child_exprs.append(string[prev_idx + 1 : idx])
                prev_idx = idx
        if depth == 0 and bool(tag) and bool(child_exprs):
            return tag, child_exprs
        else:
            raise Exception("Malformed miniscript string.")

    @staticmethod
    def _decompose_script(expr_list):
        idx = 0
        while idx < len(expr_list):
            if expr_list[idx] == OP_CHECKSIGVERIFY:
                expr_list = (
                    expr_list[:idx] + [OP_CHECKSIG, OP_VERIFY] + expr_list[idx + 1 :]
                )
            elif expr_list[idx] == OP_CHECKMULTISIGVERIFY:
                expr_list = (
                    expr_list[:idx]
                    + [OP_CHECKMULTISIG, OP_VERIFY]
                    + expr_list[idx + 1 :]
                )
            elif expr_list[idx] == OP_EQUALVERIFY:
                expr_list = (
                    expr_list[:idx] + [OP_EQUAL, OP_VERIFY] + expr_list[idx + 1 :]
                )
            idx += 1
        return expr_list


class Just0(Node):
    def __init__(self):
        Node.__init__(self)

        self.t = Fragment.JUST_0
        self.p = Property("Bzudems")
        self._script = [OP_0]

    def __repr__(self):
        return "0"


class Just1(Node):
    def __init__(self):
        Node.__init__(self)

        self.t = Fragment.JUST_1
        self.p = Property("Bzufm")
        self._script = [OP_1]

    def __repr__(self):
        return "1"


class PkNode(Node):
    def __init__(self, pubkey):
        Node.__init__(self)

        if isinstance(pubkey, bytes) or isinstance(pubkey, str):
            self.pubkey = MiniscriptKey(pubkey)
        elif isinstance(pubkey, MiniscriptKey):
            self.pubkey = pubkey
        else:
            raise MiniscriptNodeCreationError("Invalid pubkey for pk_k node")

        self.t = Fragment.PK_K
        self.p = Property("Konudems")
        self._script = [self.pubkey.bytes()]

    def __repr__(self):
        return f"pk_k({self.pubkey.bytes().hex()})"


class PkhNode(Node):
    def __init__(self, pk_or_pkh):
        Node.__init__(self)

        if (
            isinstance(pk_or_pkh, bytes)
            and len(pk_or_pkh) == 33
            or isinstance(pk_or_pkh, str)
            and len(pk_or_pkh) == 66
        ):
            self.pk_or_pkh = MiniscriptKey(pk_or_pkh)
        elif isinstance(pk_or_pkh, bytes) and len(pk_or_pkh) == 20:
            self.pk_or_pkh = pk_or_pkh
        elif isinstance(pk_or_pkh, str) and len(pk_or_pkh) == 40:
            self.pk_or_pkh = bytes.fromhex(pk_or_pkh)
        elif isinstance(pk_or_pkh, MiniscriptKey):
            self.pk_or_pkh = pk_or_pkh
        else:
            raise MiniscriptNodeCreationError("Invalid pubkey or hash for pk_h node")

        self.t = Fragment.PK_H
        self.p = Property("Knudems")
        self._script = [OP_DUP, OP_HASH160, self.pk_hash(), OP_EQUALVERIFY]

    def __repr__(self):
        if isinstance(self.pk_or_pkh, MiniscriptKey):
            return f"pk_h({self.pk_or_pkh.bytes().hex()})"
        else:
            assert isinstance(self.pk_or_pkh, bytes)
            return f"pk_h({self.pk_or_pkh.hex()})"

    def pk_hash(self):
        if isinstance(self.pk_or_pkh, MiniscriptKey):
            return hash160(self.pk_or_pkh.bytes())
        assert isinstance(self.pk_or_pkh, bytes)
        if len(self.pk_or_pkh) == 20:
            return self.pk_or_pkh
        else:
            assert len(self.pk_or_pkh) == 33
            return hash160(self.pk_or_pkh)


class Older(Node):
    def __init__(self, value):
        assert value > 0 and value < 2 ** 31

        self.value = value
        self.t = Fragment.OLDER
        self.p = Property("Bzmf")
        self._script = [self.value, OP_CHECKSEQUENCEVERIFY]

    def __repr__(self):
        return f"older({self.value})"


class After(Node):
    def __init__(self, value):
        assert value > 0 and value < 2 ** 31

        self.value = value
        self.t = Fragment.AFTER
        self.p = Property("Bzmf")
        self._script = [self.value, OP_CHECKLOCKTIMEVERIFY]

    def __repr__(self):
        return f"after({self.value})"


class Sha256(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 32

        self.digest = digest
        self.t = Fragment.SHA256
        self.p = Property("Bonudm")
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, digest, OP_EQUAL]

    def __repr__(self):
        return f"sha256({self.digest.hex()})"


class Hash256(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 32

        self.digest = digest
        self.t = Fragment.HASH256
        self.p = Property("Bonudm")
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH256, digest, OP_EQUAL]

    def __repr__(self):
        return f"hash256({self.digest.hex()})"


class Ripemd160(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 20

        self.digest = digest
        self.t = Fragment.RIPEMD160
        self.p = Property("Bonudm")
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_RIPEMD160, digest, OP_EQUAL]

    def __repr__(self):
        return f"ripemd160({self.digest.hex()})"


class Hash160(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 20

        self.digest = digest
        self.t = Fragment.HASH160
        self.p = Property("Bonudm")
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH160, digest, OP_EQUAL]

    def __repr__(self):
        return f"hash160({self.digest.hex()})"


class Multi(Node):
    def __init__(self, k, keys):
        assert 1 <= k <= len(keys)

        self.t = Fragment.MULTI
        self.k = k
        self.keys = keys
        self.p = Property("Bndu")
        self._script = [k, *[k.bytes() for k in keys], len(keys), OP_CHECKMULTISIG]

    def __repr__(self):
        return f"multi({','.join([self.k] + self.keys)})"


class AndV(Node):
    def __init__(self, child_x, child_y):
        assert child_x.p.V
        assert child_y.p.has_any("BKV")

        # FIXME: don't use properties for malleability tracking
        self.t = Fragment.AND_V
        self.p = Property(
            child_y.p.type()
            + ("z" if child_x.p.z and child_y.p.z else "")
            + (
                "o"
                if child_x.p.z and child_y.p.o or child_x.p.o and child_y.p.z
                else ""
            )
            + ("n" if child_x.p.n or child_x.p.z and child_y.p.n else "")
            + ("u" if child_y.p.u else "")
            + ("f" if child_y.p.f or child_x.p.s else "")
            + ("s" if child_x.p.s or child_y.p.s else "")
            + ("m" if child_x.p.m and child_y.p.m else "")
        )
        self.subs = [child_x, child_y]

        self._script = child_x._script + child_y._script
        # TODO: satisfaction

    def __repr__(self):
        return f"and_v({','.join(self.subs)})"


class AndB(Node):
    def __init__(self, child_x, child_y):
        assert child_x.p.B and child_y.p.W

        # FIXME: don't use properties for malleability tracking
        self.t = Fragment.AND_B
        self.p = Property(
            "Bu"
            + ("z" if child_x.p.z and child_y.p.z else "")
            + (
                "o"
                if child_x.p.z and child_y.p.o or child_x.p.o and child_y.p.z
                else ""
            )
            + ("n" if child_x.p.n or child_x.p.z and child_y.p.n else "")
            + ("d" if child_x.p.d and child_y.p.d else "")
            + ("u" if child_y.p.u else "")
            + (
                "f"
                if child_x.p.f
                and child_y.p.f
                or any(c.p.has_all("sf") for c in [child_x, child_y])
                else ""
            )
            + ("s" if child_x.p.s or child_y.p.s else "")
            + ("m" if child_x.p.m and child_y.p.m else "")
        )
        self.subs = [child_x, child_y]

        self._script = [*child_x._script, *child_y._script, OP_BOOLAND]
        # TODO: satisfaction

    def __repr__(self):
        return f"and_b({','.join(self.subs)})"


class OrB(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bd")
        assert sub_z.p.has_all("Wd")

        self.t = Fragment.OR_B
        self.p = Property(
            "Bdu"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.z and sub_z.p.o or sub_x.p.o and sub_z.p.z else "")
            + ("f" if sub_x.p.f or sub_z.p.f else "")
            + ("s" if sub_x.p.s and sub_z.p.s else "")
            + (
                "m"
                if sub_x.p.m
                and sub_z.p.m
                and sub_x.p.e
                and sub_z.p.e
                and (sub_x.p.s or sub_z.p.s)
                else ""
            )
        )
        self.subs = [sub_x, sub_z]

        self._script = [*sub_x._script, *sub_z._script, OP_BOOLOR]
        # TODO: satisfaction

    def __repr__(self):
        return f"or_b({','.join(self.subs)})"


class OrC(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu") and sub_z.p.V

        self.t = Fragment.OR_C
        self.p = Property(
            "V"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
            + ("f" if sub_x.p.f or sub_z.p.f else "")
            + ("s" if sub_x.p.s and sub_z.p.s else "")
            + (
                "m"
                if sub_x.p.m and sub_z.p.m and sub_x.p.e and (sub_x.p.s or sub_z.p.s)
                else ""
            )
        )
        self.subs = [sub_x, sub_z]

        self._script = [*sub_x._script, OP_NOTIF, *sub_z._script, OP_ENDIF]
        # TODO: satisfaction

    def __repr__(self):
        return f"or_c({','.join(self.subs)})"


class OrD(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu")
        assert sub_z.p.has_all("B")

        self.t = Fragment.OR_D
        self.p = Property(
            "B"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
            + ("d" if sub_z.p.d else "")
            + ("u" if sub_z.p.u else "")
            + ("f" if sub_x.p.f or sub_z.p.f else "")
            + ("s" if sub_x.p.s and sub_z.p.s else "")
            + ("e" if sub_x.p.e and sub_z.p.e else "")
            + (
                "m"
                if sub_x.p.m and sub_z.p.m and sub_x.p.e and (sub_x.p.s or sub_z.p.s)
                else ""
            )
        )
        self.subs = [sub_x, sub_z]

        self._script = [*sub_x._script, OP_IFDUP, OP_NOTIF, *sub_z._script, OP_ENDIF]
        # TODO: satisfaction

    def __repr__(self):
        return f"or_d({','.join(self.subs)})"


class OrI(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.type() == sub_z.p.type() and sub_x.p.has_any("BKV")

        self.t = Fragment.OR_I
        self.p = Property(
            sub_x.p.type()
            + ("o" if sub_x.p.z and sub_z.p.z else "")
            + ("d" if sub_x.p.d or sub_z.p.d else "")
            + ("u" if sub_x.p.u and sub_z.p.u else "")
            + ("f" if sub_x.p.f and sub_z.p.f else "")
            + ("s" if sub_x.p.s and sub_z.p.s else "")
            + ("e" if (sub_x.p.e and sub_z.p.f) or (sub_x.p.f and sub_z.p.e) else "")
            + ("m" if sub_x.p.m and sub_z.p.m and (sub_x.p.s or sub_z.p.s) else "")
        )
        self.subs = [sub_x, sub_z]

        self._script = [OP_IF, *sub_x._script, OP_ELSE, *sub_z._script, OP_ENDIF]

    def __repr__(self):
        return f"or_i({','.join(self.subs)})"


class AndOr(Node):
    # FIXME: rename all 'child' to 'sub'
    def __init__(self, child_x, child_y, child_z):
        assert child_x.p.has_all("Bdu")
        assert child_y.p.type() == child_z.p.type() and child_y.p.has_any("BKV")

        self.t = Fragment.ANDOR
        self.p = Property(
            child_y.p.type()
            + ("z" if child_x.p.z and child_y.p.z and child_z.p.z else "")
            + (
                "o"
                if child_x.p.z
                and child_y.p.o
                and child_z.p.o
                or child_x.p.o
                and child_y.p.z
                and child_z.p.z
                else ""
            )
            + ("d" if child_z.p.d else "")
            + ("u" if child_y.p.u and child_z.p.u else "")
            + ("f" if child_z.p.f and (child_x.p.s or child_y.p.f) else "")
            + (
                "e"
                if child_x.p.e and child_z.p.e and (child_x.p.s or child_y.p.f)
                else ""
            )
            + (
                "m"
                if child_x.p.m
                and child_y.p.m
                and child_z.p.m
                and child_x.p.e
                and (child_x.p.s or child_y.p.s or child_z.p.s)
                else ""
            )
            + ("s" if child_z.p.s and (child_x.p.s or child_y.p.s) else "")
        )
        self.subs = [child_x, child_y, child_z]

        self._script = [
            *child_x._script,
            OP_NOTIF,
            *child_z._script,
            OP_ELSE,
            *child_y._script,
            OP_ENDIF,
        ]
        # TODO: satisfaction

    def __repr__(self):
        return f"andor({','.join(self.subs)})"


class AndN(AndOr):
    def __init__(self, sub_x, sub_y):
        AndOr.__init__(self, sub_x, sub_y, Just0())

    def __repr__(self):
        return f"and_n({self.subs[0]},{self.subs[1]})"


class Thresh(Node):
    def __init__(self, k, subs):
        n = len(subs)
        assert 1 <= k <= n

        all_z = True
        all_z_but_one_odu = False
        all_e = True
        all_m = True
        s_count = 0
        assert subs[0].p.has_all("Bdu")
        for sub in subs[1:]:
            assert sub.p.has_all("Wdu")
            if not sub.p.z:
                if all_z_but_one_odu:
                    # Fails "all 'z' but one"
                    all_z_but_one_odu = False
                if all_z and sub.p.has_all("odu"):
                    # They were all 'z' up to now.
                    all_z_but_one_odu = True
                all_z = False
            all_e = all_e and sub.p.e
            all_m = all_m and sub.p.m
            if sub.p.s:
                s_count += 1

        self.t = Fragment.THRESH
        self.p = Property(
            "B"
            + ("z" if all_z else "")
            + ("o" if all_z_but_one_odu else "")
            + ("e" if all_e and s_count == n else "")
            + ("m" if all_e and all_m and s_count >= n - k else "")
            + ("s" if s_count >= n - k + 1 else "")
        )
        self.k = k
        self.subs = subs
        self._script = subs[0]._script
        for sub in subs[1:]:
            self._script += [*sub._script, OP_ADD]
        self._script += [k, OP_EQUAL]

    def __repr__(self):
        return f"thresh({self.k},{''.join(self.subs)})"


class WrapA(Node):
    def __init__(self, sub):
        assert sub.p.B

        self.t = Fragment.WRAP_A
        self.p = Property("W" + "".join(c for c in "udfems" if getattr(sub.p, c)))
        self.subs = [sub]
        self._script = [OP_TOALTSTACK, *sub._script, OP_FROMALTSTACK]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"a{self.subs[0]}"
        return f"a:{self.subs[0]}"


class WrapS(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Bo")

        self.t = Fragment.WRAP_S
        self.p = Property("W" + "".join(c for c in "udfems" if getattr(sub.p, c)))
        self.subs = [sub]
        self._script = [OP_SWAP, *sub._script]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"s{self.subs[0]}"
        return f"s:{self.subs[0]}"


class WrapC(Node):
    def __init__(self, sub):
        assert sub.p.K

        self.t = Fragment.WRAP_C
        # FIXME: shouldn't n and d be default props on the website?
        self.p = Property("Bsndu" + ("o" if sub.p.o else ""))
        self.subs = [sub]
        self._script = [*sub._script, OP_CHECKSIG]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"c{self.subs[0]}"
        return f"c:{self.subs[0]}"


# FIXME: shouldn't we just ser/deser the AndV class specifically instead?
class WrapT(AndV):
    def __init__(self, sub):
        AndV.__init__(self, sub, Just1())
        self.t = Fragment.WRAP_T

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"t{self.subs[0]}"
        return f"t:{self.subs[0]}"


class WrapD(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Vz")

        self.t = Fragment.WRAP_D
        self.p = Property("Bondu" + "".join(c for c in "ems" if getattr(sub.p, c)))
        self.subs = [sub]
        self._script = [OP_DUP, OP_IF, *sub._script, OP_ENDIF]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"d{self.subs[0]}"
        return f"d:{self.subs[0]}"


class WrapV(Node):
    def __init__(self, sub):
        assert sub.p.B

        self.t = Fragment.WRAP_V
        self.p = Property("Vf" + "".join(c for c in "zonems" if getattr(sub.p, c)))
        self.subs = [sub]
        if sub._script[-1] == OP_CHECKSIG:
            self._script = [*sub._script[:-1], OP_CHECKSIGVERIFY]
        elif sub._script[-1] == OP_CHECKMULTISIG:
            self._script = [*sub._script[:-1], OP_CHECKMULTISIGVERIFY]
        elif sub._script[-1] == OP_EQUAL:
            self._script = [*sub._script[:-1], OP_EQUALVERIFY]
        else:
            self._script = [*sub._script, OP_VERIFY]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"v{self.subs[0]}"
        return f"v:{self.subs[0]}"


class WrapJ(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Bn")

        self.t = Fragment.WRAP_J
        self.p = Property("Bnd" + "".join(c for c in "ouems" if getattr(sub.p, c)))
        self.subs = [sub]
        self._script = [OP_SIZE, OP_0NOTEQUAL, OP_IF, *sub._script, OP_ENDIF]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"j{self.subs[0]}"
        return f"j:{self.subs[0]}"


class WrapN(Node):
    def __init__(self, sub):
        assert sub.p.B

        self.t = Fragment.WRAP_J
        self.p = Property("Bu" + "".join(c for c in "zondfems" if getattr(sub.p, c)))
        self.subs = [sub]
        self._script = [*sub._script, OP_0NOTEQUAL]

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"n{self.subs[0]}"
        return f"n:{self.subs[0]}"


class WrapL(OrI):
    def __init__(self, sub):
        OrI.__init__(self, Just0(), sub)
        self.t = Fragment.WRAP_L

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"l{self.subs[0]}"
        return f"l:{self.subs[0]}"


class WrapU(OrI):
    def __init__(self, sub):
        OrI.__init__(self, sub, Just0())
        self.t = Fragment.WRAP_U

    def __repr__(self):
        # Avoid duplicating colons
        if str(self.subs[0])[1] == ":":
            return f"u{self.subs[0]}"
        return f"u:{self.subs[0]}"
