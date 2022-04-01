# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Classes and methods to encode and decode miniscripts"""
import hashlib

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
        if isinstance(item, Just1):
            return 1
        if isinstance(item, Just0):
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


class Node:
    """A Miniscript fragment."""

    def __init__(self):
        # The fragment's type and properties
        self.p = None
        # List of all sub fragments
        self.subs = []
        # A list of Script elements, a CScript is created all at once in the script() method.
        self._script = []
        # Whether any satisfaction for this fragment require a signature
        self.needs_sig = None
        # Whether any dissatisfaction for this fragment requires a signature
        self.is_forced = None
        # Whether this fragment has a unique unconditional satisfaction, and all conditional
        # ones require a signature.
        self.is_expressive = None
        # Whether for any possible way to satisfy this fragment (may be none), a
        # non-malleable satisfaction exists.
        self.is_nonmalleable = None

    def __repr__(self):
        return f"(k = {self._k}, pk_k = {[k.hex() for k in self._pk_k]}, pk_h = {self._pk_h})"

    @staticmethod
    def from_str(string):
        """Construct miniscript node from string representation"""
        tag, sub_exprs = Node._parse_string(string)
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
            return AndV(*Node._parse_sub_strings(sub_exprs))

        if tag == "and_b":
            return AndB(*Node._parse_sub_strings(sub_exprs))

        if tag == "and_n":
            return AndN(*Node._parse_sub_strings(sub_exprs))

        if tag == "or_b":
            return OrB(*Node._parse_sub_strings(sub_exprs))

        if tag == "or_c":
            return OrC(*Node._parse_sub_strings(sub_exprs))

        if tag == "or_d":
            return OrD(*Node._parse_sub_strings(sub_exprs))

        if tag == "or_i":
            return OrI(*Node._parse_sub_strings(sub_exprs))

        if tag == "andor":
            return AndOr(*Node._parse_sub_strings(sub_exprs))

        if tag == "thresh":
            k = int(sub_exprs.pop(0))
            return Thresh(k, Node._parse_sub_strings(sub_exprs))

        if tag == "a":
            return WrapA(*Node._parse_sub_strings(sub_exprs))

        if tag == "s":
            return WrapS(*Node._parse_sub_strings(sub_exprs))

        if tag == "c":
            return WrapC(*Node._parse_sub_strings(sub_exprs))

        if tag == "t":
            return WrapT(*Node._parse_sub_strings(sub_exprs))

        if tag == "d":
            return WrapD(*Node._parse_sub_strings(sub_exprs))

        if tag == "v":
            return WrapV(*Node._parse_sub_strings(sub_exprs))

        if tag == "j":
            return WrapJ(*Node._parse_sub_strings(sub_exprs))

        if tag == "n":
            return WrapN(*Node._parse_sub_strings(sub_exprs))

        if tag == "l":
            return WrapL(*Node._parse_sub_strings(sub_exprs))

        if tag == "u":
            return WrapU(*Node._parse_sub_strings(sub_exprs))

        assert False, (tag, sub_exprs)  # TODO

    # TODO: have something like BuildScript from Core and get rid of the _script member.
    @property
    def script(self):
        return CScript(self._script)

    @staticmethod
    def from_script(script):
        """Construct miniscript node from script"""
        # Decompose script:
        # OP_CHECKSIGVERIFY > OP_CHECKSIG + OP_VERIFY
        # OP_CHECKMULTISIGVERIFY > OP_CHECKMULTISIG + OP_VERIFY
        # OP_EQUALVERIFY > OP_EQUAL + OP_VERIFY
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
    def _parse_sub_strings(sub_exprs):
        sub_nodes = []
        for string in sub_exprs:
            sub_nodes.append(Node.from_str(string))
        return sub_nodes

    @staticmethod
    def _parse_string(string):
        string = "".join(string.split())
        tag = ""
        sub_exprs = []
        depth = 0

        for idx, ch in enumerate(string):
            if (ch == "0" or ch == "1") and len(string) == 1:
                return ch, sub_exprs
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
                    sub_exprs.append(string[prev_idx + 1 : idx])
            if ch == "," and depth == 1:
                sub_exprs.append(string[prev_idx + 1 : idx])
                prev_idx = idx
        if depth == 0 and bool(tag) and bool(sub_exprs):
            return tag, sub_exprs
        else:
            raise Exception("Malformed miniscript string.")


class Just0(Node):
    def __init__(self):
        Node.__init__(self)

        self._script = [OP_0]

        self.p = Property("Bzud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True

    def __repr__(self):
        return "0"


class Just1(Node):
    def __init__(self):
        Node.__init__(self)

        self._script = [OP_1]

        self.p = Property("Bzufm")
        self.needs_sig = False
        self.is_forced = True  # No dissat
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True  # FIXME: how comes? Standardness rules?

    def __repr__(self):
        return "1"


# TODO: maybe have parent classes like "PkNode", "HashNode"
class Pk(Node):
    def __init__(self, pubkey):
        Node.__init__(self)

        if isinstance(pubkey, bytes) or isinstance(pubkey, str):
            self.pubkey = MiniscriptKey(pubkey)
        elif isinstance(pubkey, MiniscriptKey):
            self.pubkey = pubkey
        else:
            raise MiniscriptNodeCreationError("Invalid pubkey for pk_k node")
        self._script = [self.pubkey.bytes()]

        self.p = Property("Konud")
        self.needs_sig = True  # FIXME: doesn't make much sense, keep it in 'c:'
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True

    def __repr__(self):
        return f"pk_k({self.pubkey.bytes().hex()})"


class Pkh(Node):
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
        self._script = [OP_DUP, OP_HASH160, self.pk_hash(), OP_EQUALVERIFY]

        self.p = Property("Knud")
        self.needs_sig = True  # FIXME: see pk()
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True

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
        Node.__init__(self)

        self.value = value
        self._script = [self.value, OP_CHECKSEQUENCEVERIFY]

        self.p = Property("Bz")
        self.needs_sig = False
        self.is_forced = True
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True

    def __repr__(self):
        return f"older({self.value})"


class After(Node):
    def __init__(self, value):
        assert value > 0 and value < 2 ** 31
        Node.__init__(self)

        self.value = value
        self._script = [self.value, OP_CHECKLOCKTIMEVERIFY]

        self.p = Property("Bz")
        self.needs_sig = False
        self.is_forced = True
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True

    def __repr__(self):
        return f"after({self.value})"


class Sha256(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 32
        Node.__init__(self)

        self.digest = digest
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, digest, OP_EQUAL]

        self.p = Property("Bonud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True

    def __repr__(self):
        return f"sha256({self.digest.hex()})"


class Hash256(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 32
        Node.__init__(self)

        self.digest = digest
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH256, digest, OP_EQUAL]

        self.p = Property("Bonud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True

    def __repr__(self):
        return f"hash256({self.digest.hex()})"


class Ripemd160(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 20
        Node.__init__(self)

        self.digest = digest
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True

        self.p = Property("Bonud")
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_RIPEMD160, digest, OP_EQUAL]

    def __repr__(self):
        return f"ripemd160({self.digest.hex()})"


class Hash160(Node):
    def __init__(self, digest):
        assert isinstance(digest, bytes) and len(digest) == 20
        Node.__init__(self)

        self.digest = digest
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH160, digest, OP_EQUAL]

        self.p = Property("Bonud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True

    def __repr__(self):
        return f"hash160({self.digest.hex()})"


class Multi(Node):
    def __init__(self, k, keys):
        assert 1 <= k <= len(keys)
        assert all(isinstance(k, MiniscriptKey) for k in keys)
        Node.__init__(self)

        self.k = k
        self.keys = keys
        self._script = [k, *[k.bytes() for k in keys], len(keys), OP_CHECKMULTISIG]

        self.p = Property("Bndu")
        self.needs_sig = True
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True  # FIXME: why? Standardness rules?

    def __repr__(self):
        return (
            f"multi({','.join([str(self.k)] + [k.bytes().hex() for k in self.keys])})"
        )


class AndV(Node):
    def __init__(self, sub_x, sub_y):
        assert sub_x.p.V
        assert sub_y.p.has_any("BKV")
        Node.__init__(self)

        self.subs = [sub_x, sub_y]
        self._script = sub_x._script + sub_y._script

        self.p = Property(
            sub_y.p.type()
            + ("z" if sub_x.p.z and sub_y.p.z else "")
            + ("o" if sub_x.p.z and sub_y.p.o or sub_x.p.o and sub_y.p.z else "")
            + ("n" if sub_x.p.n or sub_x.p.z and sub_y.p.n else "")
            + ("u" if sub_y.p.u else "")
        )
        self.needs_sig = any(sub.needs_sig for sub in self.subs)
        self.is_forced = any(sub.needs_sig for sub in self.subs)
        self.is_expressive = False  # Not 'd'
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs)

        # TODO: satisfaction

    def __repr__(self):
        return f"and_v({','.join(map(str, self.subs))})"


class AndB(Node):
    def __init__(self, sub_x, sub_y):
        assert sub_x.p.B and sub_y.p.W
        Node.__init__(self)

        self.subs = [sub_x, sub_y]
        self._script = [*sub_x._script, *sub_y._script, OP_BOOLAND]

        self.p = Property(
            "Bu"
            + ("z" if sub_x.p.z and sub_y.p.z else "")
            + ("o" if sub_x.p.z and sub_y.p.o or sub_x.p.o and sub_y.p.z else "")
            + ("n" if sub_x.p.n or sub_x.p.z and sub_y.p.n else "")
            + ("d" if sub_x.p.d and sub_y.p.d else "")
            + ("u" if sub_y.p.u else "")
            + (
                "f"
                if sub_x.p.f
                and sub_y.p.f
                or any(c.p.has_all("sf") for c in [sub_x, sub_y])
                else ""
            )
        )
        self.needs_sig = any(sub.needs_sig for sub in self.subs)
        self.is_forced = (
            sub_x.is_forced
            and sub_y.is_forced
            or any(sub.is_forced and sub.needs_sig for sub in self.subs)
        )
        self.is_expressive = all(sub.is_forced and sub.needs_sig for sub in self.subs)
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs)

        # TODO: satisfaction

    def __repr__(self):
        return f"and_b({','.join(map(str, self.subs))})"


class OrB(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bd")
        assert sub_z.p.has_all("Wd")
        Node.__init__(self)

        self.subs = [sub_x, sub_z]
        self._script = [*sub_x._script, *sub_z._script, OP_BOOLOR]

        self.p = Property(
            "Bdu"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.z and sub_z.p.o or sub_x.p.o and sub_z.p.z else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = False  # Both subs are 'd'
        self.is_expressive = all(sub.is_expressive for sub in self.subs)
        self.is_nonmalleable = all(
            sub.is_nonmalleable and sub.is_expressive for sub in self.subs
        ) and any(sub.needs_sig for sub in self.subs)
        # TODO: satisfaction

    def __repr__(self):
        return f"or_b({','.join(map(str, self.subs))})"


class OrC(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu") and sub_z.p.V
        Node.__init__(self)

        self.subs = [sub_x, sub_z]
        self._script = [*sub_x._script, OP_NOTIF, *sub_z._script, OP_ENDIF]

        self.p = Property(
            "V"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = True  # Because sub_z is 'V'
        self.is_expressive = False  # V
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )

        # TODO: satisfaction

    def __repr__(self):
        return f"or_c({','.join(map(str, self.subs))})"


class OrD(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu")
        assert sub_z.p.has_all("B")
        Node.__init__(self)

        self.subs = [sub_x, sub_z]
        self._script = [*sub_x._script, OP_IFDUP, OP_NOTIF, *sub_z._script, OP_ENDIF]

        self.p = Property(
            "B"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
            + ("d" if sub_z.p.d else "")
            + ("u" if sub_z.p.u else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = all(sub.is_forced for sub in self.subs)
        self.is_expressive = all(sub.is_expressive for sub in self.subs)
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )

        # TODO: satisfaction

    def __repr__(self):
        return f"or_d({','.join(map(str, self.subs))})"


class OrI(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.type() == sub_z.p.type() and sub_x.p.has_any("BKV")
        Node.__init__(self)

        self.subs = [sub_x, sub_z]
        self._script = [OP_IF, *sub_x._script, OP_ELSE, *sub_z._script, OP_ENDIF]

        self.p = Property(
            sub_x.p.type()
            + ("o" if sub_x.p.z and sub_z.p.z else "")
            + ("d" if sub_x.p.d or sub_z.p.d else "")
            + ("u" if sub_x.p.u and sub_z.p.u else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = all(sub.is_forced for sub in self.subs)
        self.is_expressive = (
            sub_x.is_expressive
            and sub_z.is_forced
            or sub_x.is_forced
            and sub_z.is_expressive
        )
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs) and any(
            sub.needs_sig for sub in self.subs
        )

    def __repr__(self):
        return f"or_i({','.join(map(str, self.subs))})"


class AndOr(Node):
    def __init__(self, sub_x, sub_y, sub_z):
        assert sub_x.p.has_all("Bdu")
        assert sub_y.p.type() == sub_z.p.type() and sub_y.p.has_any("BKV")
        Node.__init__(self)

        self.subs = [sub_x, sub_y, sub_z]
        self._script = [
            *sub_x._script,
            OP_NOTIF,
            *sub_z._script,
            OP_ELSE,
            *sub_y._script,
            OP_ENDIF,
        ]

        self.p = Property(
            sub_y.p.type()
            + ("z" if sub_x.p.z and sub_y.p.z and sub_z.p.z else "")
            + (
                "o"
                if sub_x.p.z
                and sub_y.p.o
                and sub_z.p.o
                or sub_x.p.o
                and sub_y.p.z
                and sub_z.p.z
                else ""
            )
            + ("d" if sub_z.p.d else "")
            + ("u" if sub_y.p.u and sub_z.p.u else "")
        )
        self.needs_sig = sub_x.needs_sig and (sub_y.needs_sig or sub_z.needs_sig)
        self.is_forced = sub_z.is_forced and (sub_x.needs_sig or sub_y.is_forced)
        self.is_expressive = (
            sub_x.is_expressive
            and sub_z.is_expressive
            and (sub_x.needs_sig or sub_y.is_forced)
        )
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )

        # TODO: satisfaction

    def __repr__(self):
        return f"andor({','.join(map(str, self.subs))})"


class AndN(AndOr):
    def __init__(self, sub_x, sub_y):
        AndOr.__init__(self, sub_x, sub_y, Just0())

    def __repr__(self):
        return f"and_n({self.subs[0]},{self.subs[1]})"


class Thresh(Node):
    def __init__(self, k, subs):
        n = len(subs)
        assert 1 <= k <= n
        Node.__init__(self)

        self.k = k
        self.subs = subs
        self._script = subs[0]._script
        for sub in subs[1:]:
            self._script += [*sub._script, OP_ADD]
        self._script += [k, OP_EQUAL]

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

        self.p = Property(
            "B" + ("z" if all_z else "") + ("o" if all_z_but_one_odu else "")
        )
        self.needs_sig = s_count >= n - k
        self.is_forced = False  # All subs need to be 'd'
        self.is_expressive = all_e and s_count == n
        self.is_nonmalleable = all_e and s_count >= n - k

    def __repr__(self):
        return f"thresh({self.k},{','.join(map(str, self.subs))})"


def is_wrapper(node):
    """Whether the given node is a wrapper or not."""
    return isinstance(
        node, (WrapA, WrapS, WrapC, WrapD, WrapV, WrapJ, WrapL, WrapU, WrapT)
    )


class WrapA(Node):
    def __init__(self, sub):
        assert sub.p.B
        Node.__init__(self)

        self.subs = [sub]
        self._script = [OP_TOALTSTACK, *sub._script, OP_FROMALTSTACK]

        self.p = Property("W" + "".join(c for c in "ud" if getattr(sub.p, c)))
        self.needs_sig = sub.needs_sig
        self.is_forced = sub.is_forced
        self.is_expressive = sub.is_expressive
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        if is_wrapper(self.subs[0]):
            return f"a{self.subs[0]}"
        return f"a:{self.subs[0]}"


class WrapS(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Bo")
        Node.__init__(self)

        self.subs = [sub]
        self._script = [OP_SWAP, *sub._script]

        self.p = Property("W" + "".join(c for c in "ud" if getattr(sub.p, c)))
        self.needs_sig = sub.needs_sig
        self.is_forced = sub.is_forced
        self.is_expressive = sub.is_expressive
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"s{self.subs[0]}"
        return f"s:{self.subs[0]}"


class WrapC(Node):
    def __init__(self, sub):
        assert sub.p.K
        Node.__init__(self)

        self.subs = [sub]
        self._script = [*sub._script, OP_CHECKSIG]

        # FIXME: shouldn't n and d be default props on the website?
        self.p = Property("Bsndu" + ("o" if sub.p.o else ""))
        self.needs_sig = True
        self.is_forced = sub.is_forced
        self.is_expressive = sub.is_expressive
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"c{self.subs[0]}"
        return f"c:{self.subs[0]}"


# FIXME: shouldn't we just ser/deser the AndV class specifically instead?
class WrapT(AndV):
    def __init__(self, sub):
        AndV.__init__(self, sub, Just1())

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"t{self.subs[0]}"
        return f"t:{self.subs[0]}"


class WrapD(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Vz")
        Node.__init__(self)

        self.subs = [sub]
        self._script = [OP_DUP, OP_IF, *sub._script, OP_ENDIF]

        self.p = Property("Bondu")
        self.needs_sig = sub.needs_sig
        self.is_forced = True  # sub is V
        self.is_expressive = True  # sub is V, and we add a single dissat
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"d{self.subs[0]}"
        return f"d:{self.subs[0]}"


class WrapV(Node):
    def __init__(self, sub):
        assert sub.p.B
        Node.__init__(self)

        self.subs = [sub]
        if sub._script[-1] == OP_CHECKSIG:
            self._script = [*sub._script[:-1], OP_CHECKSIGVERIFY]
        elif sub._script[-1] == OP_CHECKMULTISIG:
            self._script = [*sub._script[:-1], OP_CHECKMULTISIGVERIFY]
        elif sub._script[-1] == OP_EQUAL:
            self._script = [*sub._script[:-1], OP_EQUALVERIFY]
        else:
            self._script = [*sub._script, OP_VERIFY]

        self.p = Property("Vf" + "".join(c for c in "zon" if getattr(sub.p, c)))
        self.needs_sig = sub.needs_sig
        self.is_forced = True  # V
        self.is_expressive = False  # V
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"v{self.subs[0]}"
        return f"v:{self.subs[0]}"


class WrapJ(Node):
    def __init__(self, sub):
        assert sub.p.has_all("Bn")
        Node.__init__(self)

        self.subs = [sub]
        self._script = [OP_SIZE, OP_0NOTEQUAL, OP_IF, *sub._script, OP_ENDIF]

        self.p = Property("Bnd" + "".join(c for c in "ou" if getattr(sub.p, c)))
        self.needs_sig = sub.needs_sig
        self.is_forced = False  # d
        self.is_expressive = sub.is_forced
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"j{self.subs[0]}"
        return f"j:{self.subs[0]}"


class WrapN(Node):
    def __init__(self, sub):
        assert sub.p.B
        Node.__init__(self)

        self.subs = [sub]
        self._script = [*sub._script, OP_0NOTEQUAL]

        self.p = Property("Bu" + "".join(c for c in "zond" if getattr(sub.p, c)))
        self.needs_sig = sub.needs_sig
        self.is_forced = sub.is_forced
        self.is_expressive = sub.is_expressive
        self.is_nonmalleable = sub.is_nonmalleable

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"n{self.subs[0]}"
        return f"n:{self.subs[0]}"


class WrapL(OrI):
    def __init__(self, sub):
        OrI.__init__(self, Just0(), sub)

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"l{self.subs[0]}"
        return f"l:{self.subs[0]}"


class WrapU(OrI):
    def __init__(self, sub):
        OrI.__init__(self, sub, Just0())

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"u{self.subs[0]}"
        return f"u:{self.subs[0]}"
