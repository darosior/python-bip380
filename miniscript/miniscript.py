# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Classes and methods to encode and decode miniscripts"""
import hashlib

from enum import Enum
from itertools import product

from .key import MiniscriptKey
from .property import Property
from .script import (
    CScript,
    CScriptOp,
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


class NodeType(Enum):
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


class SatType(Enum):
    # SatType Class provides information on how to construct satisfying or
    # non-satisfying witnesses. sat/dsat methods return list of tuples:
    # [(SatType, Value), (SatType, Value), ...]
    # The value provides a hint how to construct the resp. witness element.
    OLDER = 0  # Value: Delay
    AFTER = 1  # Value: Time
    SIGNATURE = 2  # Value: 33B Key/20B HASH160 Digest
    KEY_AND_HASH160_PREIMAGE = 3  # Value: 20B HASH160 Digest
    SHA256_PREIMAGE = 4  # Value: 32B SHA256 Digest
    HASH256_PREIMAGE = 5  # Value: 32B HASH256 Digest
    RIPEMD160_PREIMAGE = 6  # Value: 20B RIPEMD160 Digest
    HASH160_PREIMAGE = 7  # Value: 20B HASH160 Digest
    DATA = 8  # Value: Bytes


def stack_item_to_int(item):
    """
    Convert a stack item to an integer depending on its type.
    May raise an exception if the item is bytes, otherwise return None if it
    cannot perform the conversion.
    """
    if isinstance(item, bytes):
        return read_script_number(item)

    if isinstance(item, Node):
        if item.t == NodeType.JUST_1:
            return 1
        if item.t == NodeType.JUST_0:
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
        key = MiniscriptKey(expr_list[idx])
        expr_list[idx] = Node().construct_pk_k(key)

    # Match against JUST_1 and JUST_0.
    if expr_list[idx] == 1:
        expr_list[idx] = Node().construct_just_1()
    if expr_list[idx] == 0:
        expr_list[idx] = Node().construct_just_0()


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
        node = Node().construct_older(n)
        expr_list[idx : idx + 2] = [node]
        return expr_list

    if elem_b == OP_CHECKLOCKTIMEVERIFY:
        node = Node().construct_after(n)
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

    node = Node().construct_pk_h(expr_list[idx + 2])
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
        node = Node().construct_sha256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash256.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_HASH256]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 32
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Node().construct_hash256(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against ripemd160.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_RIPEMD160]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 20
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Node().construct_ripemd160(expr_list[idx + 5])
        expr_list[idx : idx + 7] = [node]
        return expr_list

    # Match against hash160.
    if (
        expr_list[idx : idx + 5] == [OP_SIZE, 32, OP_EQUAL, OP_VERIFY, OP_HASH160]
        and isinstance(expr_list[idx + 5], bytes)
        and len(expr_list[idx + 5]) == 20
        and expr_list[idx + 6] == OP_EQUAL
    ):
        node = Node().construct_hash160(expr_list[idx + 5])
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
            if elem_b.t == NodeType.JUST_1:
                node = Node().construct_t(elem_a, elem_b)
            else:
                node = Node().construct_and_v(elem_a, elem_b)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against c wrapper.
        if elem_b == OP_CHECKSIG and elem_a.p.K:
            node = Node().construct_c(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against v wrapper.
        if elem_b == OP_VERIFY and elem_a.p.B:
            node = Node().construct_v(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

        # Match against n wrapper.
        if elem_b == OP_0NOTEQUAL and elem_a.p.B:
            node = Node().construct_n(elem_a)
            expr_list[idx : idx + 2] = [node]
            return expr_list

    # Match against s wrapper.
    if isinstance(elem_b, Node) and elem_a == OP_SWAP and elem_b.p.has_all("Bo"):
        node = Node().construct_s(elem_b)
        expr_list[idx : idx + 2] = [node]
        return expr_list


def parse_nonterm_3_elems(expr_list, idx):
    """
    Try to parse a non-terminal node from two elements of {expr_list}, starting
    from {idx}.
    Return the new expression list on success, None on error.
    """
    elem_a = expr_list[idx]
    elem_b = expr_list[idx + 1]
    elem_c = expr_list[idx + 2]

    if isinstance(elem_a, Node) and isinstance(elem_b, Node):
        # Match against and_b.
        if elem_c == OP_BOOLAND and elem_a.p.B and elem_b.p.W:
            node = Node().construct_and_b(elem_a, elem_b)
            expr_list[idx : idx + 3] = [node]
            return expr_list

        # Match against or_b.
        if elem_c == OP_BOOLOR and elem_a.p.has_all("Bd") and elem_b.p.has_all("Wd"):
            node = Node().construct_or_b(elem_a, elem_b)
            expr_list[idx : idx + 3] = [node]
            return expr_list

    # Match against a wrapper.
    if (
        elem_a == OP_TOALTSTACK
        and isinstance(elem_b, Node)
        and elem_b.p.B
        and elem_c == OP_FROMALTSTACK
    ):
        node = Node().construct_a(elem_b)
        expr_list[idx : idx + 3] = [node]
        return expr_list


class Node:
    """Miniscript expression class

    Provides methods to instantiate a miniscript node from a string descriptor
    or script. Node.sat, Node.dsat, Node.sat_ncan and Node.dsat_ncan return a
    list of tuples which encode the (dis)satisfying witness stack.
    """

    def __init__(self):
        # TODO: rename (or remove..)
        self.desc = ""
        self.children = None
        self.t = None
        self._sat = None
        self._k = None
        self._pk_k = []
        self._pk_h = []

    def __repr__(self):
        return f"{self.t}(k = {self._k}, pk_k = {[k.hex() for k in self._pk_k]}, pk_h = {self._pk_h})"

    # TODO: rename..
    @staticmethod
    def from_desc(string):
        """Construct miniscript node from string descriptor"""
        tag, child_exprs = Node._parse_string(string)
        k = None

        if tag == "0":
            return Node().construct_just_0()

        if tag == "1":
            return Node().construct_just_1()

        if tag == "pk":
            key_obj = MiniscriptKey(child_exprs[0])
            return Node().construct_c(Node().construct_pk_k(key_obj))

        if tag == "pk_k":
            key_obj = MiniscriptKey(child_exprs[0])
            return Node().construct_pk_k(key_obj)

        if tag == "pkh":
            keyhash = bytes.fromhex(child_exprs[0])
            return Node().construct_c(Node().construct_pk_h(keyhash))

        if tag == "pk_h":
            keyhash_b = bytes.fromhex(child_exprs[0])
            return Node().construct_pk_h(keyhash_b)

        if tag == "older":
            n = int(child_exprs[0])
            return Node().construct_older(n)

        if tag == "after":
            # FIXME: rename
            time = int(child_exprs[0])
            return Node().construct_after(time)

        if tag in ["sha256", "hash256", "ripemd160", "hash160"]:
            hash_b = bytes.fromhex(child_exprs[0])
            return getattr(Node(), "construct_" + tag)(hash_b)

        if tag == "multi":
            k = int(child_exprs.pop(0))
            key_n = []
            for child_expr in child_exprs:
                key_obj = MiniscriptKey(child_expr)
                key_n.append(key_obj)
            return Node().construct_multi(k, key_n)

        if tag == "thresh":
            k = int(child_exprs.pop(0))
            return Node().construct_thresh(k, Node._parse_child_strings(child_exprs))

        # Standard node constructor forms:
        # construct_tag(node_x, node_y, ...):
        return getattr(Node(), "construct_" + tag)(
            *Node._parse_child_strings(child_exprs)
        )

    @property
    def script(self):
        return CScript(Node._collapse_script(self._script))

    @staticmethod
    def from_script(c_script):
        """Construct miniscript node from script"""
        # FIXME: avoid looping 45678 times ..
        expr_list = []
        for op in c_script:
            # Encode 0, 20, 32 as int.
            # Other values are coerced to int types with Node._coerce_to_int()
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

            # 4 element expressions.
            if expr_list_len - idx >= 4:

                # Match against thresh. It's of the form [X] ([X] ADD)* k EQUAL
                node_a = expr_list[idx]
                if (
                    isinstance(node_a, Node)
                    and node_a.p.has_all("Bdu")
                ):
                    subs = [node_a]
                    # The first matches, now do all the ([X] ADD)s and return
                    # if a pair is of the form (k, EQUAL).
                    for i in range(idx + 1, expr_list_len - 1, 2):
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
                                    node = Node().construct_thresh(k, subs)
                                    expr_list[idx : i + 1 + 1] = [node]
                                    return Node()._parse_expr_list(expr_list)
                            except ScriptNumError:
                                break
                        else:
                            break

                # Match against or_c.
                if (
                    isinstance(expr_list[idx], Node)
                    and expr_list[idx + 1] == OP_NOTIF
                    and isinstance(expr_list[idx + 2], Node)
                    and expr_list[idx + 3] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_or_c(expr_list[idx], expr_list[idx + 2])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 4 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against d wrapper.
                if (
                    expr_list[idx : idx + 2] == [OP_DUP, OP_IF]
                    and isinstance(expr_list[idx + 2], Node)
                    and expr_list[idx + 3] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_d(expr_list[idx + 2])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 4 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

            # 5 element expressions.
            if expr_list_len - idx >= 5:

                # Match against or_d.
                if (
                    isinstance(expr_list[idx], Node)
                    and expr_list[idx + 1 : idx + 3] == [OP_IFDUP, OP_NOTIF]
                    and isinstance(expr_list[idx + 3], Node)
                    and expr_list[idx + 4] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_or_d(expr_list[idx], expr_list[idx + 3])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 5 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against or_i.
                if (
                    expr_list[idx] == OP_IF
                    and isinstance(expr_list[idx + 1], Node)
                    and expr_list[idx + 2] == OP_ELSE
                    and isinstance(expr_list[idx + 3], Node)
                    and expr_list[idx + 4] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_or_i(
                            expr_list[idx + 1], expr_list[idx + 3]
                        )
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 5 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against j wrapper.
                if (
                    expr_list[idx : idx + 3] == [OP_SIZE, OP_0NOTEQUAL, OP_IF]
                    and isinstance(expr_list[idx + 3], Node)
                    and expr_list[idx + 4] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_j(expr_list[idx + 3])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 5 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against l wrapper.
                if (
                    expr_list[idx] == OP_IF
                    and isinstance(expr_list[idx + 1], Node)
                    and expr_list[idx + 1].t == NodeType.JUST_0
                    and expr_list[idx + 2] == OP_ELSE
                    and isinstance(expr_list[idx + 3], Node)
                    and expr_list[idx + 4] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_l(expr_list[idx + 3])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 5 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against u wrapper.
                if (
                    expr_list[idx] == OP_IF
                    and isinstance(expr_list[idx + 1], Node)
                    and expr_list[idx + 2 : idx + 5] == [OP_ELSE, 0, OP_ENDIF]
                ):
                    try:
                        node = Node().construct_u(expr_list[idx + 1])
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 5 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

            # 6 element expressions.
            if expr_list_len - idx >= 6:

                # Match against and_n.
                if (
                    isinstance(expr_list[idx], Node)
                    and expr_list[idx + 1] == OP_NOTIF
                    and isinstance(expr_list[idx + 2], Node)
                    and expr_list[idx + 2].t == NodeType.JUST_0
                    and expr_list[idx + 3] == OP_ELSE
                    and isinstance(expr_list[idx + 4], Node)
                    and expr_list[idx + 5] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_and_n(
                            expr_list[idx], expr_list[idx + 4]
                        )
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 6 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

                # Match against andor.
                if (
                    isinstance(expr_list[idx], Node)
                    and expr_list[idx + 1] == OP_NOTIF
                    and isinstance(expr_list[idx + 2], Node)
                    and expr_list[idx + 3] == OP_ELSE
                    and isinstance(expr_list[idx + 4], Node)
                    and expr_list[idx + 5] == OP_ENDIF
                ):
                    try:
                        node = Node().construct_andor(
                            expr_list[idx], expr_list[idx + 4], expr_list[idx + 2]
                        )
                        expr_list = expr_list[:idx] + [node] + expr_list[idx + 6 :]
                        return Node._parse_expr_list(expr_list)
                    except Exception:
                        pass

            # Match against multi.
            # Termainal expression, but k and n values can be Nodes (JUST_0/1)
            if expr_list_len - idx >= 3 and (
                (
                    isinstance(expr_list[idx], int)
                    and expr_list_len - idx - 3 >= expr_list[idx] >= 1
                )
                or (
                    isinstance(expr_list[idx], Node)
                    and expr_list[idx].t == NodeType.JUST_1
                )
            ):
                k = Node._coerce_to_int(expr_list[idx])
                # Permissible values for n:
                # len(expr)-3 >= n >= 1
                for n in range(idx, expr_list_len - 2):
                    # Match ... <PK_K>*n ...
                    match, pk_m = True, []
                    for i in range(n):
                        if not (
                            isinstance(expr_list[idx + 1 + i], Node)
                            and expr_list[idx + 1 + i].t == NodeType.PK_K
                        ):
                            match = False
                            break
                        else:
                            key = MiniscriptKey(expr_list[idx + 1 + i]._pk_k[0])
                            pk_m.append(key)
                    # Match ... <m> <OP_CHECKMULTISIG>
                    if match is True:
                        m = Node._coerce_to_int(expr_list[idx + n + 1])
                        if (
                            isinstance(m, int)
                            and m == len(pk_m)
                            and expr_list[idx + n + 2] == OP_CHECKMULTISIG
                        ):
                            try:
                                node = Node().construct_multi(k, pk_m)
                                expr_list = (
                                    expr_list[:idx] + [node] + expr_list[idx + n + 3 :]
                                )
                                return Node._parse_expr_list(expr_list)
                            except Exception:
                                pass

            # Right-to-left parsing.
            # Step one position left.
            idx -= 1

        # No match found.
        raise Exception("Malformed miniscript")

    def _lift_sat(self):
        # Return satisfying witnesses if terminal node.
        if not self.children:
            return self._sat()
        child_sat_set_ls, child_dsat_set_ls = self._generate_child_sat_dsat()
        return self._lift_function(self._sat, child_sat_set_ls, child_dsat_set_ls)

    def _lift_dsat(self):
        # Return non-satisfying witness if terminal node.
        if not self.children:
            return self._dsat()
        child_sat_set_ls, child_dsat_set_ls = self._generate_child_sat_dsat()
        return self._lift_function(self._dsat, child_sat_set_ls, child_dsat_set_ls)

    def _lift_function(self, function, child_sat_set_ls, child_dsat_set_ls):
        # Applies (d)sat function on all child_sat_set x child_dsat_set
        # permutations. Returns list of unique (dis)satisfying witnesses.
        ret_ls = []
        for child_sat_set in child_sat_set_ls:
            for child_dsat_set in child_dsat_set_ls:
                for ret in function(child_sat_set, child_dsat_set):
                    if ret not in ret_ls:
                        # Order (d)sat elements with OLDER/AFTER
                        # SatType elements at beginning.
                        ret_older = []
                        ret_after = []
                        ret_ordered = []
                        valid = True
                        for element in ret:
                            # Handle None element from children,
                            # which represents lack of non-cannonical (d)sat.
                            if element is None:
                                valid = False
                                break
                            else:
                                if element[0] == SatType.OLDER:
                                    ret_older.append(element)
                                elif element[0] == SatType.AFTER:
                                    ret_after.append(element)
                                else:
                                    ret_ordered.append(element)
                        if valid is True:
                            ret_ordered = ret_older + ret_after + ret_ordered
                            # Append ordered (d)sat.
                            ret_ls.append(ret_ordered)
        return ret_ls

    def _generate_child_sat_dsat(self):
        # Create list of lists of unique satisfying witnesses for each child.
        # [
        # [satx', satx'', satx'''],
        # [saty', saty'', saty'''],
        # [satz', satz'', satz''']
        # ]
        child_sat_var_ls = []
        child_dsat_var_ls = []
        for child in self.children:
            child_sat_var_ls.append(child.sat)  # what if multiple are returned?
            child_dsat_var_ls.append(child.dsat)

        # Generate all permutations of sets each containing a single satisfying
        # witness element from each child.
        # [
        # [satx', saty', satz'],
        # [satx', saty', satz''],
        # [satx', saty'', satz''],
        # [satx'', saty'', satz''],
        # [satx'', saty'', satz'],
        # [satx'', saty', satz'], ...
        # ]

        # List iterators are reusable.
        child_sat_set_ls = list(product(*child_sat_var_ls))
        child_dsat_set_ls = list(product(*child_dsat_var_ls))
        return child_sat_set_ls, child_dsat_set_ls

    @property
    def sat_ncan(self):
        """Retrieve non-canonical satisfactions of miniscript object"""
        if self._sat_ncan == [[None]]:
            return []
        else:
            return self._sat_ncan

    @property
    def dsat_ncan(self):
        """Retrieve non-canonical dissatisfactions of miniscript object"""
        if self._dsat_ncan == [[None]]:
            return []
        else:
            return self._dsat_ncan

    def _lift_sat_ncan(self):
        if not self.children:
            return [[None]]

        (
            child_sat_n_can_set_ls,
            child_dsat_n_can_set_ls,
        ) = self._generate_child_sat_dsat_ncan()

        sat_ncan_ls = self._lift_function(
            self._sat, child_sat_n_can_set_ls, child_dsat_n_can_set_ls
        )
        sat_ncan_ls += self._lift_function(
            self._sat_ncan, child_sat_n_can_set_ls, child_dsat_n_can_set_ls
        )

        # Check if already in sat_can
        sat__ncan_ls_ret = []
        for sat_ncan in sat_ncan_ls:
            if sat_ncan not in self.sat:
                sat__ncan_ls_ret.append(sat_ncan)
        if len(sat__ncan_ls_ret) == 0:
            return [[None]]
        else:
            return sat__ncan_ls_ret

    def _lift_dsat_ncan(self):
        if not self.children:
            return [[None]]

        (
            child_sat_n_can_set_ls,
            child_dsat_n_can_set_ls,
        ) = self._generate_child_sat_dsat_ncan()

        dsat_ncan_ls = self._lift_function(
            self._dsat, child_sat_n_can_set_ls, child_dsat_n_can_set_ls
        )
        dsat_ncan_ls += self._lift_function(
            self._dsat_ncan, child_sat_n_can_set_ls, child_dsat_n_can_set_ls
        )

        # Check if already in dsat_can
        dsat__ncan_ls_ret = []
        for dsat_ncan in dsat_ncan_ls:
            if dsat_ncan not in self.dsat:
                dsat__ncan_ls_ret.append(dsat_ncan)
        if len(dsat__ncan_ls_ret) == 0:
            return [[None]]
        else:
            return dsat__ncan_ls_ret

    def _generate_child_sat_dsat_ncan(self):
        child_sat_n_can_var_ls = []
        child_dsat_n_can_var_ls = []

        for child in self.children:
            child_sat_n_can_var_ls.append(child.sat + child._sat_ncan)
            child_dsat_n_can_var_ls.append(child.dsat + child._dsat_ncan)

        # List iterators are reusable.
        child_sat_n_can_set_ls = list(product(*child_sat_n_can_var_ls))
        child_dsat_n_can_set_ls = list(product(*child_dsat_n_can_var_ls))

        return (child_sat_n_can_set_ls, child_dsat_n_can_set_ls)

    def construct_just_1(self):
        self._construct(
            NodeType.JUST_1,
            Property("Bzufm"),
            [],
            self._just_1_sat,
            self._just_1_dsat,
            [1],
            "1",
        )
        return self

    def construct_just_0(self):
        self._construct(
            NodeType.JUST_0,
            Property("Bzudems"),
            [],
            self._just_0_sat,
            self._just_0_dsat,
            [0],
            "0",
        )
        return self

    def construct_pk_k(self, pubkey):
        self._pk_k = [pubkey.bytes()]
        self._construct(
            NodeType.PK_K,
            Property("Konudems"),
            [],
            self._pk_k_sat,
            self._pk_k_dsat,
            [pubkey.bytes()],
            "pk_k(" + self._pk_k[0].hex() + ")",
        )
        return self

    def construct_pk_h(self, pk_or_pkhash):
        """Can be either a key or a keyhash, for now."""
        assert isinstance(pk_or_pkhash, bytes) and len(pk_or_pkhash) in [20, 33]
        if len(pk_or_pkhash) == 20:
            h = pk_or_pkhash
        else:
            self._pk_k = pk_or_pkhash
            h = hash160(pk_or_pkhash)
        self._pk_h = h
        self._construct(
            NodeType.PK_H,
            Property("Knudems"),
            [],
            self._pk_h_sat,
            self._pk_h_dsat,
            [OP_DUP, OP_HASH160, h, OP_EQUALVERIFY],
            "pk_h(" + h.hex() + ")",
        )
        return self

    def construct_older(self, delay):
        assert delay > 0 and delay < 2 ** 31
        self._delay = delay
        self._construct(
            NodeType.OLDER,
            Property("Bzfm"),
            [],
            self._older_sat,
            self._older_dsat,
            [delay, OP_CHECKSEQUENCEVERIFY],
            "older(" + str(delay) + ")",
        )
        return self

    def construct_after(self, time):
        assert time >= 1 and time < 2 ** 31
        # FIXME: rename this, 'time' is confusing
        self._time = time
        self._construct(
            NodeType.AFTER,
            Property("Bzfm"),
            [],
            self._after_sat,
            self._after_dsat,
            [time, OP_CHECKLOCKTIMEVERIFY],
            "after(" + str(time) + ")",
        )
        return self

    def construct_sha256(self, hash_digest):
        assert isinstance(hash_digest, bytes) and len(hash_digest) == 32
        self._sha256 = hash_digest
        self._construct(
            NodeType.SHA256,
            Property("Bonudm"),
            [],
            self._sha256_sat,
            self._sha256_dsat,
            [OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, hash_digest, OP_EQUAL],
            "sha256(" + hash_digest.hex() + ")",
        )
        return self

    def construct_hash256(self, hash_digest):
        assert isinstance(hash_digest, bytes) and len(hash_digest) == 32
        self._hash256 = hash_digest
        self._construct(
            NodeType.HASH256,
            Property("Bonudm"),
            [],
            self._hash256_sat,
            self._hash256_dsat,
            [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH256, hash_digest, OP_EQUAL],
            "hash256(" + hash_digest.hex() + ")",
        )
        return self

    def construct_ripemd160(self, hash_digest):
        assert isinstance(hash_digest, bytes) and len(hash_digest) == 20
        self._ripemd160 = hash_digest
        self._construct(
            NodeType.RIPEMD160,
            Property("Bonudm"),
            [],
            self._ripemd160_sat,
            self._ripemd160_dsat,
            [OP_SIZE, 32, OP_EQUALVERIFY, OP_RIPEMD160, hash_digest, OP_EQUAL],
            "ripemd160(" + hash_digest.hex() + ")",
        )
        return self

    def construct_hash160(self, hash_digest):
        assert isinstance(hash_digest, bytes) and len(hash_digest) == 20
        self._hash160 = hash_digest
        self._construct(
            NodeType.HASH160,
            Property("Bonudm"),
            [],
            self._hash160_sat,
            self._hash160_dsat,
            [OP_SIZE, 32, OP_EQUALVERIFY, OP_HASH160, hash_digest, OP_EQUAL],
            "hash160(" + hash_digest.hex() + ")",
        )
        return self

    def construct_multi(self, k, keys_n):
        self._k = k
        n = len(keys_n)
        assert n >= k >= 1
        prop_str = "Bnudems"
        self._pk_n = [key.bytes() for key in keys_n]
        desc = "multi(" + str(k) + ","
        for idx, key_b in enumerate(self._pk_n):
            desc += key_b.hex()
            desc += "," if idx != (n - 1) else ")"
        self._construct(
            NodeType.MULTI,
            Property(prop_str),
            [],
            self._multi_sat,
            self._multi_dsat,
            [k, *self._pk_n, n, OP_CHECKMULTISIG],
            desc,
        )
        return self

    def construct_and_v(self, child_x, child_y):
        assert child_x.p.V
        assert child_y.p.has_any("BKV")

        prop_str = ""
        prop_str += "B" if child_x.p.V and child_y.p.B else ""
        prop_str += "K" if child_x.p.V and child_y.p.K else ""
        prop_str += "V" if child_x.p.V and child_y.p.V else ""
        prop_str += "u" if child_y.p.u else ""
        prop_str += "n" if child_x.p.n or (child_x.p.z and child_y.p.n) else ""
        prop_str += "z" if child_x.p.z and child_y.p.z else ""
        prop_str += (
            "o"
            if (child_x.p.z and child_y.p.o) or (child_x.p.o and child_y.p.z)
            else ""
        )
        prop_str += "f" if child_x.p.s or child_y.p.f else ""
        prop_str += "m" if child_x.p.m and child_y.p.m else ""
        prop_str += "s" if child_x.p.s or child_y.p.s else ""
        self._construct(
            NodeType.AND_V,
            Property(prop_str),
            [child_x, child_y],
            self._and_v_sat,
            self._and_v_dsat,
            child_x._script + child_y._script,
            "and_v(" + child_x.desc + "," + child_y.desc + ")",
        )
        return self

    def construct_and_b(self, child_x, child_y):
        assert child_x.p.B and child_y.p.W

        prop_str = "u"
        prop_str += "B" if child_x.p.B and child_y.p.W else ""
        prop_str += "z" if child_x.p.z and child_y.p.z else ""
        prop_str += (
            "o"
            if (child_x.p.z and child_y.p.o) or (child_x.p.o and child_y.p.z)
            else ""
        )
        prop_str += "n" if child_x.p.n or (child_x.p.z and child_y.p.n) else ""
        prop_str += "d" if child_x.p.d and child_y.p.d else ""
        prop_str += (
            "f"
            if (child_x.p.f and child_y.p.f)
            or (child_x.p.s and child_x.p.f)
            or (child_y.p.s and child_y.p.f)
            else ""
        )
        prop_str += (
            "e" if child_x.p.e and child_y.p.e and child_x.p.s and child_y.p.s else ""
        )
        prop_str += "m" if child_x.p.m and child_y.p.m else ""
        prop_str += "s" if child_x.p.s or child_y.p.s else ""
        self._construct(
            NodeType.AND_B,
            Property(prop_str),
            [child_x, child_y],
            self._and_b_sat,
            self._and_b_dsat,
            child_x._script + child_y._script + [OP_BOOLAND],
            "and_b(" + child_x.desc + "," + child_y.desc + ")",
        )
        return self

    def construct_and_n(self, child_x, child_y):
        assert child_x.p.d and child_x.p.u
        assert (child_x.p.f and child_y.p.f) is False
        prop_str = "d"
        prop_str += "B" if child_x.p.B and child_y.p.B else ""
        prop_str += "z" if child_x.p.z and child_y.p.z else ""
        prop_str += "o" if child_x.p.o and child_y.p.z else ""
        prop_str += "u" if child_y.p.u else ""
        prop_str += "e" if child_x.p.e and (child_x.p.s or child_y.p.f) else ""
        prop_str += "m" if child_x.p.m and child_y.p.m and child_x.p.e else ""
        prop_str += "s" if child_x.p.s or child_y.p.s else ""
        self._construct(
            NodeType.AND_N,
            Property(prop_str),
            [child_x, child_y],
            self._and_n_sat,
            self._and_n_dsat,
            child_x._script + [OP_NOTIF, 0, OP_ELSE] + child_y._script + [OP_ENDIF],
            "and_n(" + child_x.desc + "," + child_y.desc + ")",
        )
        return self

    def construct_or_b(self, child_x, child_z):
        assert child_x.p.has_all("Bd")
        assert child_z.p.has_all("Wd")

        prop_str = "du"
        prop_str += "B" if child_x.p.B and child_z.p.W else ""
        prop_str += "z" if child_x.p.z and child_z.p.z else ""
        prop_str += (
            "o"
            if (child_x.p.z and child_z.p.o) or (child_x.p.o and child_z.p.z)
            else ""
        )
        prop_str += "e" if child_x.p.e and child_z.p.e else ""
        prop_str += (
            "m"
            if child_x.p.m
            and child_z.p.m
            and child_x.p.e
            and child_z.p.e
            and (child_x.p.s or child_z.p.s)
            else ""
        )
        prop_str += "s" if child_x.p.s and child_z.p.s else ""
        self._construct(
            NodeType.OR_B,
            Property(prop_str),
            [child_x, child_z],
            self._or_b_sat,
            self._or_b_dsat,
            child_x._script + child_z._script + [OP_BOOLOR],
            "or_b(" + child_x.desc + "," + child_z.desc + ")",
        )
        return self

    def construct_or_d(self, child_x, child_z):
        assert child_x.p.has_all("Bdu")
        assert child_z.p.B

        prop_str = ""
        prop_str += "B" if child_x.p.B and child_z.p.B else ""
        prop_str += "z" if child_x.p.z and child_z.p.z else ""
        prop_str += "o" if child_x.p.o and child_z.p.z else ""
        prop_str += "u" if child_x.p.u and (child_x.p.f or child_z.p.u) else ""
        prop_str += "d" if child_x.p.d and child_z.p.d else ""
        prop_str += "f" if child_x.p.f or child_z.p.f else ""
        prop_str += "e" if child_x.p.e and child_z.p.e else ""
        prop_str += (
            "m"
            if child_x.p.m
            and child_z.p.m
            and child_x.p.e
            and (child_x.p.s or child_z.p.s)
            else ""
        )
        prop_str += "s" if child_x.p.s and child_z.p.s else ""
        self._construct(
            NodeType.OR_D,
            Property(prop_str),
            [child_x, child_z],
            self._or_d_sat,
            self._or_d_dsat,
            child_x._script + [OP_IFDUP, OP_NOTIF] + child_z._script + [OP_ENDIF],
            "or_d(" + child_x.desc + "," + child_z.desc + ")",
        )
        return self

    def construct_or_c(self, child_x, child_z):
        assert child_x.p.has_all("Bdu") and child_z.p.V
        prop_str = ""
        prop_str += "V" if child_x.p.B and child_z.p.V else ""
        prop_str += "z" if child_x.p.z and child_z.p.z else ""
        prop_str += "o" if child_x.p.o and child_z.p.z else ""
        prop_str += "f" if child_x.p.f or child_z.p.f else ""
        prop_str += (
            "m"
            if child_x.p.m
            and child_z.p.m
            and child_x.p.e
            and (child_x.p.s or child_z.p.s)
            else ""
        )
        prop_str += "s" if child_x.p.s and child_z.p.s else ""
        self._construct(
            NodeType.OR_C,
            Property(prop_str),
            [child_x, child_z],
            self._or_c_sat,
            self._or_c_dsat,
            child_x._script + [OP_NOTIF] + child_z._script + [OP_ENDIF],
            "or_c(" + child_x.desc + "," + child_z.desc + ")",
        )
        return self

    def construct_or_i(self, child_x, child_z):
        for child in child_x, child_z:
            assert child.p.has_any("BKV")

        prop_str = ""
        prop_str += "B" if child_x.p.B and child_z.p.B else ""
        prop_str += "K" if child_x.p.K and child_z.p.K else ""
        prop_str += "V" if child_x.p.V and child_z.p.V else ""
        prop_str += "u" if child_x.p.u and child_z.p.u else ""
        prop_str += "d" if child_x.p.d or child_z.p.d else ""
        prop_str += "o" if child_x.p.z and child_z.p.z else ""
        prop_str += (
            "e"
            if (child_x.p.e and child_z.p.f) or (child_x.p.f and child_z.p.e)
            else ""
        )
        prop_str += "f" if child_x.p.f and child_z.p.f else ""
        prop_str += (
            "m" if child_x.p.m and child_z.p.m and (child_x.p.s or child_z.p.s) else ""
        )
        prop_str += "s" if child_x.p.s and child_z.p.s else ""
        self._construct(
            NodeType.OR_I,
            Property(prop_str),
            [child_x, child_z],
            self._or_i_sat,
            self._or_i_dsat,
            [OP_IF] + child_x._script + [OP_ELSE] + child_z._script + [OP_ENDIF],
            "or_i(" + child_x.desc + "," + child_z.desc + ")",
        )
        return self

    def construct_andor(self, child_x, child_y, child_z):
        assert child_x.p.has_all("Bdu")
        for child in child_y, child_z:
            assert child.p.has_any("BKV")

        prop_str = ""
        prop_str += "B" if child_x.p.B and child_y.p.B and child_z.p.B else ""
        prop_str += "K" if child_x.p.B and child_y.p.K and child_z.p.K else ""
        prop_str += "V" if child_x.p.B and child_y.p.V and child_z.p.V else ""
        prop_str += "z" if child_x.p.z and child_y.p.z and child_z.p.z else ""
        prop_str += (
            "o"
            if (child_x.p.z and child_y.p.o and child_z.p.o)
            or (child_x.p.o and child_y.p.z and child_z.p.z)
            else ""
        )
        prop_str += "u" if child_y.p.u and child_z.p.u else ""
        prop_str += "d" if child_x.p.d and child_z.p.d else ""
        prop_str += "f" if child_z.p.f and (child_x.p.s or child_y.p.f) else ""
        prop_str += (
            "e" if child_x.p.e and child_z.p.e and (child_x.p.s or child_y.p.f) else ""
        )
        prop_str += (
            "m"
            if child_x.p.m
            and child_y.p.m
            and child_z.p.m
            and child_x.p.e
            and (child_x.p.s or child_y.p.s or child_z.p.s)
            else ""
        )
        prop_str += "s" if child_z.p.s and (child_x.p.s or child_y.p.s) else ""
        self._construct(
            NodeType.ANDOR,
            Property(prop_str),
            [child_x, child_y, child_z],
            self._andor_sat,
            self._andor_dsat,
            child_x._script
            + [OP_NOTIF]
            + child_z._script
            + [OP_ELSE]
            + child_y._script
            + [OP_ENDIF],
            "andor(" + child_x.desc + "," + child_y.desc + "," + child_z.desc + ")",
        )
        return self

    def construct_a(self, child_x):
        prop_str = ""
        prop_str += "W" if child_x.p.B else ""
        prop_str += "u" if child_x.p.u else ""
        prop_str += "d" if child_x.p.d else ""
        prop_str += "f" if child_x.p.f else ""
        prop_str += "e" if child_x.p.e else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "a" if child_x.t.name.startswith("WRAP_") else "a:"
        self._construct(
            NodeType.WRAP_A,
            Property(prop_str),
            [child_x],
            self._a_sat,
            self._a_dsat,
            [OP_TOALTSTACK] + child_x._script + [OP_FROMALTSTACK],
            tag + child_x.desc,
        )
        return self

    def construct_s(self, child_x):
        assert child_x.p.B and child_x.p.o
        prop_str = "W"
        prop_str += "u" if child_x.p.u else ""
        prop_str += "d" if child_x.p.d else ""
        prop_str += "f" if child_x.p.f else ""
        prop_str += "e" if child_x.p.e else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "s" if child_x.t.name.startswith("WRAP_") else "s:"
        self._construct(
            NodeType.WRAP_S,
            Property(prop_str),
            [child_x],
            self._s_sat,
            self._s_dsat,
            [OP_SWAP] + child_x._script,
            tag + child_x.desc,
        )
        return self

    def construct_c(self, child_x):
        assert child_x.p.K
        prop_str = "Bu"
        prop_str += "o" if child_x.p.o else ""
        prop_str += "n" if child_x.p.n else ""
        prop_str += "d" if child_x.p.d else ""
        prop_str += "e" if child_x.p.e else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "c" if child_x.t.name.startswith("WRAP_") else "c:"
        self._construct(
            NodeType.WRAP_C,
            Property(prop_str),
            [child_x],
            self._c_sat,
            self._c_dsat,
            child_x._script + [OP_CHECKSIG],
            tag + child_x.desc,
        )
        return self

    def construct_t(self, child_x):
        assert child_x.p.V
        prop_str = "uf"
        prop_str += "B" if child_x.p.V else ""
        prop_str += "n" if child_x.p.n else ""
        prop_str += "z" if child_x.p.z else ""
        prop_str += "o" if child_x.p.o else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "t" if child_x.t.name.startswith("WRAP_") else "t:"
        self._construct(
            NodeType.WRAP_T,
            Property(prop_str),
            [child_x],
            self._t_sat,
            self._t_dsat,
            child_x._script + [1],
            tag + child_x.desc,
        )
        return self

    def construct_d(self, child_x):
        assert child_x.p.has_all("Vz")
        prop_str = "nud"
        prop_str += "B" if child_x.p.V else ""
        prop_str += "o" if child_x.p.z else ""
        prop_str += "e" if child_x.p.f else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "d" if child_x.t.name.startswith("WRAP_") else "d:"
        self._construct(
            NodeType.WRAP_D,
            Property(prop_str),
            [child_x],
            self._d_sat,
            self._d_dsat,
            [OP_DUP, OP_IF] + child_x._script + [OP_ENDIF],
            tag + child_x.desc,
        )
        return self

    def construct_v(self, child_x):
        assert child_x.p.B
        prop_str = "V"
        prop_str += "z" if child_x.p.z else ""
        prop_str += "o" if child_x.p.o else ""
        prop_str += "n" if child_x.p.n else ""
        prop_str += "f"
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "v" if child_x.t.name.startswith("WRAP_") else "v:"
        # Combine OP_CHECKSIG/OP_CHECKMULTISIG/OP_EQUAL with OP_VERIFY.
        if child_x._script[-1] == OP_CHECKSIG:
            script = child_x._script[:-1] + [OP_CHECKSIGVERIFY]
        elif child_x._script[-1] == OP_CHECKMULTISIG:
            script = child_x._script[:-1] + [OP_CHECKMULTISIGVERIFY]
        elif child_x._script[-1] == OP_EQUAL:
            script = child_x._script[:-1] + [OP_EQUALVERIFY]
        else:
            script = child_x._script + [OP_VERIFY]
        self._construct(
            NodeType.WRAP_V,
            Property(prop_str),
            [child_x],
            self._v_sat,
            self._v_dsat,
            script,
            tag + child_x.desc,
        )
        return self

    def construct_j(self, child_x):
        assert child_x.p.has_all("Bn")
        prop_str = "nd"
        prop_str += "B" if child_x.p.B else ""
        prop_str += "o" if child_x.p.o else ""
        prop_str += "u" if child_x.p.u else ""
        prop_str += "e" if child_x.p.f else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "j" if child_x.t.name.startswith("WRAP_") else "j:"
        script = [OP_SIZE, OP_0NOTEQUAL, OP_IF] + child_x._script + [OP_ENDIF]
        self._construct(
            NodeType.WRAP_J,
            Property(prop_str),
            [child_x],
            self._j_sat,
            self._j_dsat,
            script,
            tag + child_x.desc,
        )
        return self

    def construct_n(self, child_x):
        assert child_x.p.B
        prop_str = "u"
        prop_str += "B" if child_x.p.B else ""
        prop_str += "z" if child_x.p.z else ""
        prop_str += "o" if child_x.p.o else ""
        prop_str += "n" if child_x.p.n else ""
        prop_str += "d" if child_x.p.d else ""
        prop_str += "f" if child_x.p.f else ""
        prop_str += "e" if child_x.p.e else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "n" if child_x.t.name.startswith("WRAP_") else "n:"
        self._construct(
            NodeType.WRAP_N,
            Property(prop_str),
            [child_x],
            self._n_sat,
            self._n_dsat,
            child_x._script + [OP_0NOTEQUAL],
            tag + child_x.desc,
        )
        return self

    def construct_l(self, child_x):
        assert child_x.p.has_any("BKV")

        prop_str = "d"
        prop_str += "B" if child_x.p.B else ""
        prop_str += "o" if child_x.p.z else ""
        prop_str += "u" if child_x.p.u else ""
        prop_str += "e" if child_x.p.f else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "l" if child_x.t.name.startswith("WRAP_") else "l:"
        script = [OP_IF, 0, OP_ELSE] + child_x._script + [OP_ENDIF]
        self._construct(
            NodeType.WRAP_L,
            Property(prop_str),
            [child_x],
            self._l_sat,
            self._l_dsat,
            script,
            tag + child_x.desc,
        )
        return self

    def construct_u(self, child_x):
        assert child_x.p.has_any("BKV")

        prop_str = "d"
        prop_str += "B" if child_x.p.B else ""
        prop_str += "o" if child_x.p.z else ""
        prop_str += "u" if child_x.p.u else ""
        prop_str += "e" if child_x.p.f else ""
        prop_str += "m" if child_x.p.m else ""
        prop_str += "s" if child_x.p.s else ""
        tag = "u" if child_x.t.name.startswith("WRAP_") else "u:"
        script = [OP_IF] + child_x._script + [OP_ELSE, 0, OP_ENDIF]
        self._construct(
            NodeType.WRAP_U,
            Property(prop_str),
            [child_x],
            self._u_sat,
            self._u_dsat,
            script,
            tag + child_x.desc,
        )
        return self

    def construct_thresh(self, k, children_n):
        n = len(children_n)
        assert n >= k >= 1
        child_is_z_count = 0
        child_is_o_count = 0
        child_is_s_count = 0
        child_is_e = True
        child_is_m = True
        for idx, child in enumerate(children_n):
            assert child.p.d and child.p.u
            child_is_z_count += 1 if child.p.z else 0
            child_is_o_count += 1 if child.p.o else 0
            child_is_s_count += 1 if child.p.s else 0
            child_is_e = child_is_e and child.p.e
            child_is_m = child_is_m and child.p.m
            if idx == 0:
                is_B = child.p.B
            else:
                is_B = is_B and child.p.W
        prop_str = "Bdu" if is_B else ""
        if child_is_z_count == n:
            prop_str += "z"
        elif (child_is_z_count == n - 1) and (child_is_o_count == 1):
            prop_str += "o"
        if child_is_e and (child_is_s_count is n):
            prop_str += "e"
        if child_is_e and child_is_m and child_is_s_count >= (n - k):
            prop_str += "m"
        if child_is_s_count >= (n - k + 1):
            prop_str += "s"
        script = []
        script.extend(children_n[0]._script)
        for child in children_n[1:]:
            script.extend(child._script + [OP_ADD])
        script.extend([k] + [OP_EQUAL])
        self._k = k

        desc = "thresh(" + str(k) + ","
        for idx, child in enumerate(children_n):
            desc += child.desc
            desc += "," if idx != (n - 1) else ")"

        self._construct(
            NodeType.THRESH,
            Property(prop_str),
            children_n,
            self._thresh_sat,
            self._thresh_dsat,
            script,
            desc,
        )
        return self

    def _construct(self, node_type, node_prop, children, sat, dsat, script, desc):
        self.t = node_type
        self.p = node_prop
        self.children = children
        self._sat = sat
        self._dsat = dsat
        self.sat = self._lift_sat()
        self.dsat = self._lift_dsat()
        self._sat_ncan = self._lift_sat_ncan()
        self._dsat_ncan = self._lift_dsat_ncan()
        self._script = script
        self.desc = desc

    # sat/dsat methods for terminal node types:
    def _just_1_sat(self):
        return [[]]

    def _just_1_dsat(self):
        return [[]]

    def _just_0_sat(self):
        return [[]]

    def _just_0_dsat(self):
        return [[]]

    def _pk_k_sat(self):
        # Returns (SIGNATURE, 33B_PK) tuple.
        return [[(SatType.SIGNATURE, self._pk_k[0])]]

    def _pk_k_dsat(self):
        return [[(SatType.DATA, b"")]]

    def _pk_h_sat(self):
        # Returns (SIGNATURE, 32B_PK_HASH) tuple.
        return [
            [
                (SatType.SIGNATURE, self._pk_h),
                (SatType.KEY_AND_HASH160_PREIMAGE, self._pk_h),
            ]
        ]

    def _pk_h_dsat(self):
        return [[(SatType.DATA, b""), (SatType.KEY_AND_HASH160_PREIMAGE, self._pk_h)]]

    def _older_sat(self):
        return [[(SatType.OLDER, self._delay)]]

    def _older_dsat(self):
        return [[]]

    def _after_sat(self):
        return [[(SatType.AFTER, self._time)]]

    def _after_dsat(self):
        return [[]]

    def _sha256_sat(self):
        return [[(SatType.SHA256_PREIMAGE, self._sha256)]]

    def _sha256_dsat(self):
        return [[(SatType.DATA, bytes(32))]]

    def _hash256_sat(self):
        return [[(SatType.HASH256_PREIMAGE, self._hash256)]]

    def _hash256_dsat(self):
        return [[(SatType.DATA, bytes(32))]]

    def _ripemd160_sat(self):
        return [[(SatType.RIPEMD160_PREIMAGE, self._ripemd160)]]

    def _ripemd160_dsat(self):
        return [[(SatType.DATA, bytes(32))]]

    def _hash160_sat(self):
        return [[(SatType.HASH160_PREIMAGE, self._hash160)]]

    def _hash160_dsat(self):
        return [[(SatType.DATA, bytes(32))]]

    def _multi_sat(self):
        multi_sat_ls = []
        n = len(self._pk_n)
        for i in range(2 ** n):
            if bin(i).count("1") == self._k:
                sat = [(SatType.DATA, b"")]
                for j in range(n):
                    if ((1 << j) & i) != 0:
                        sat.append((SatType.SIGNATURE, self._pk_n[j]))
                multi_sat_ls.append(sat)
        return multi_sat_ls

    def _multi_dsat(self):
        return [[(SatType.DATA, b"")] * (self._k + 1)]

    # sat/dsat methods for node types with children:
    # sat must return list of possible satisfying witnesses.
    # dsat must return (unique) non-satisfying witness if available.

    # child_sat_set: [child_x_sat, child_y_dsat, ...]
    # dsat child_dsat_set: [child_x_dsat, child_y_dsat, ...]

    def _and_v_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[1] + child_sat_set[0]]

    def _and_v_dsat(self, child_sat_set, child_dsat_set):
        return [[]]

    def _and_b_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[1] + child_sat_set[0]]

    def _and_b_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[1] + child_dsat_set[0]]

    def _and_n_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[1] + child_sat_set[0]]

    def _and_n_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[0]]

    def _or_b_sat(self, child_sat_set, child_dsat_set):
        return [
            child_dsat_set[1] + child_sat_set[0],
            child_sat_set[1] + child_dsat_set[0],
        ]

    def _or_b_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[1] + child_dsat_set[0]]

    def _or_d_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0], child_sat_set[1] + child_dsat_set[0]]

    def _or_d_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[1] + child_dsat_set[0]]

    def _or_c_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0], child_sat_set[1] + child_dsat_set[0]]

    def _or_c_dsat(self, child_sat_set, child_dsat_set):
        return [[]]

    def _or_i_sat(self, child_sat_set, child_dsat_set):
        return [
            child_sat_set[0] + [(SatType.DATA, b"\x01")],
            child_sat_set[1] + [(SatType.DATA, b"")],
        ]

    def _or_i_dsat(self, child_sat_set, child_dsat_set):
        return [[(SatType.DATA, b"\x01")] + child_dsat_set[1] + [(SatType.DATA, b"")]]

    def _andor_sat(self, child_sat_set, child_dsat_set):
        return [
            child_sat_set[1] + child_sat_set[0],
            child_sat_set[2] + child_dsat_set[0],
        ]

    def _andor_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[2] + child_dsat_set[0]]

    def _a_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _a_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[0]]

    def _s_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _s_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[0]]

    def _c_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _c_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[0]]

    def _t_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _t_dsat(self, child_sat_set, child_dsat_set):
        return [[]]

    def _d_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0] + [(SatType.DATA, b"\x01")]]

    def _d_dsat(self, child_sat_set, child_dsat_set):
        return [[(SatType.DATA, b"")]]

    def _v_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _v_dsat(self, child_sat_set, child_dsat_set):
        return [[]]

    def _j_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _j_dsat(self, child_sat_set, child_dsat_set):
        return [[(SatType.DATA, b"")]]

    def _n_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0]]

    def _n_dsat(self, child_sat_set, child_dsat_set):
        return [child_dsat_set[0]]

    def _l_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0] + [(SatType.DATA, b"")]]

    def _l_dsat(self, child_sat_set, child_dsat_set):
        return [[(SatType.DATA, b"\x01")]]

    def _u_sat(self, child_sat_set, child_dsat_set):
        return [child_sat_set[0] + [(SatType.DATA, b"\x01")]]

    def _u_dsat(self, child_sat_set, child_dsat_set):
        return [[(SatType.DATA, b"")]]

    def _thresh_sat(self, child_sat_set, child_dsat_set):
        thresh_sat_ls = []
        n = len(self.children)
        for i in range(2 ** n):
            if bin(i).count("1") is self._k:
                sat = []
                for j in reversed(range(n)):
                    if ((1 << j) & i) != 0:
                        sat.extend(child_sat_set[j])
                    else:
                        sat.extend(child_dsat_set[j])
                thresh_sat_ls.append(sat)
        return thresh_sat_ls

    def _thresh_dsat(self, child_sat_set, child_dsat_set):
        thres_dsat = []
        for child_dsat in child_dsat_set:
            thres_dsat.extend(child_dsat)
        return [thres_dsat]

    def _sat_ncan(self, child_sat_set, child_dsat_set):
        if self.t is NodeType.OR_B:
            return [child_sat_set[1] + child_sat_set[0]]
        else:
            return [[None]]

    def _dsat_ncan(self, child_sat_set, child_dsat_set):
        if self.t is NodeType.ANDOR:
            return [child_dsat_set[1] + child_sat_set[0]]
        elif self.t is NodeType.AND_V:
            return [child_dsat_set[1] + child_sat_set[0]]
        elif self.t is NodeType.AND_B:
            return [
                child_sat_set[1] + child_dsat_set[0],
                child_dsat_set[1] + child_sat_set[0],
            ]
        elif self.t is NodeType.THRESH:
            thresh_dsat_ls = []
            n = len(self.children)
            for i in range(2 ** n):
                if bin(i).count("1") != self._k and bin(i).count("1") != 0:
                    sat = []
                    for j in reversed(range(n)):
                        if ((1 << j) & i) != 0:
                            sat.extend(child_sat_set[j])
                        else:
                            sat.extend(child_dsat_set[j])
                    thresh_dsat_ls.append(sat)
            return thresh_dsat_ls
        elif self.t is NodeType.WRAP_J:
            return (
                [[None]]
                if child_dsat_set[0] is [(SatType.DATA, b"")]
                else [child_dsat_set[0]]
            )
        else:
            return [[None]]

    # Utility methods.
    @staticmethod
    def _coerce_to_int(expr):
        # Coerce expression to int when iterating through CScript expressions
        # after terminal expressions have been parsed.
        if isinstance(expr, bytes):
            op_int = int.from_bytes(expr, byteorder="big")
        elif isinstance(expr, Node) and expr.t == NodeType.JUST_0:
            op_int = 0
        elif isinstance(expr, Node) and expr.t == NodeType.JUST_1:
            op_int = 1
        else:
            op_int = expr
        return op_int

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

    @staticmethod
    def _collapse_script(expr_list):
        idx = 0
        while idx < len(expr_list):
            if expr_list[idx : idx + 1] == [OP_CHECKSIG, OP_VERIFY]:
                expr_list = expr_list[:idx] + [OP_CHECKSIGVERIFY] + expr_list[idx + 2 :]
            elif expr_list[idx : idx + 1] == [OP_CHECKMULTISIG, OP_VERIFY]:
                expr_list = (
                    expr_list[:idx] + [OP_CHECKMULTISIGVERIFY] + expr_list[idx + 2 :]
                )
            elif expr_list[idx : idx + 1] == [OP_EQUAL, OP_VERIFY]:
                expr_list = expr_list[:idx] + [OP_EQUALVERIFY] + expr_list[idx + 2 :]
            idx += 1
        return expr_list
