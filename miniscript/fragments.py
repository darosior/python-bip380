"""
Miniscript AST elements.

Each element correspond to a Bitcoin Script fragment, and has various type properties.
See the Miniscript website for the specification of the type system: https://bitcoin.sipa.be/miniscript/.
"""

import hashlib

from .errors import MiniscriptNodeCreationError
from .key import MiniscriptKey
from .property import Property
from .script import (
    CScript,
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
)


def hash160(data):
    """{data} must be bytes, returns ripemd160(sha256(data))"""
    sha2 = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha2).digest()


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

    # TODO: have something like BuildScript from Core and get rid of the _script member.
    @property
    def script(self):
        return CScript(self._script)


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
        if is_wrapper(self.subs[1]):
            return f"l{self.subs[1]}"
        return f"l:{self.subs[1]}"


class WrapU(OrI):
    def __init__(self, sub):
        OrI.__init__(self, sub, Just0())

    def __repr__(self):
        # Avoid duplicating colons
        if is_wrapper(self.subs[0]):
            return f"u{self.subs[0]}"
        return f"u:{self.subs[0]}"
