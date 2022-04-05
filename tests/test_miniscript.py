import hashlib
import os
import pytest

from bip32 import BIP32
from miniscript import miniscript_from_str, miniscript_from_script


def dummy_pk():
    return BIP32.from_seed(os.urandom(32)).get_pubkey_from_path("m").hex()


def dummy_h256():
    return os.urandom(32).hex()


def dummy_h160():
    return os.urandom(20).hex()


def hash160(hex):
    data = bytes.fromhex(hex)
    sha2 = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha2).digest()


hash160("01")


def roundtrip(ms_str):
    """Test we can parse to and from Script and string representation.

    Note that the Script representation does not necessarily roundtrip. However
    it must be deterministic.
    """
    node_a = miniscript_from_str(ms_str)
    node_b = miniscript_from_script(node_a.script)

    assert node_b.script == miniscript_from_script(node_b.script).script
    assert str(node_b) == str(miniscript_from_str(str(node_b)))

    return node_b


def test_simple_sanity_checks():
    """Some quick and basic sanity checks of the implem. The place to add new findings."""

    not_aliased = miniscript_from_str(
        "and_v(vc:pk_k(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),c:pk_k(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))"
    )
    aliased = miniscript_from_str(
        "and_v(v:pk(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),pk(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))"
    )
    assert aliased.script == not_aliased.script

    assert roundtrip("older(1)").value == 1
    assert roundtrip("older(255)").value == 255
    assert roundtrip("older(16407)").value == 16407
    assert roundtrip("older(1621038656)").value == 1621038656
    assert roundtrip("after(1)").value == 1
    assert roundtrip("after(255)").value == 255
    assert roundtrip("after(16407)").value == 16407
    assert roundtrip("after(1621038656)").value == 1621038656
    # CSV with a negative value
    with pytest.raises(Exception):
        miniscript_from_script(b"\x86\x92\xB2")
    # CLTV with a negative value
    with pytest.raises(Exception):
        miniscript_from_script(b"\x86\x92\xB1")

    roundtrip(f"pk({dummy_pk()})")
    roundtrip(f"pk_k({dummy_pk()})")
    roundtrip(f"pk_h({dummy_h160()})")
    roundtrip("older(100)")
    roundtrip("after(100)")
    roundtrip(f"sha256({dummy_h256()})")
    roundtrip(f"hash256({dummy_h256()})")
    roundtrip(f"ripemd160({dummy_h160()})")
    roundtrip(f"hash160({dummy_h160()})")
    roundtrip(f"multi(1,{dummy_pk()})")
    roundtrip(f"multi(1,{dummy_pk()},{dummy_pk()})")
    roundtrip(f"multi(2,{dummy_pk()},{dummy_pk()})")
    roundtrip(f"multi(2,{dummy_pk()},{dummy_pk()},{dummy_pk()})")
    roundtrip(
        f"multi(2,{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()},{dummy_pk()})"
    )
    roundtrip(f"c:pk_k({dummy_pk()})")
    roundtrip(f"c:pk_h({dummy_h160()})")
    roundtrip(f"and_v(and_v(vc:pk_h({dummy_h160()}),vc:pk_h({dummy_h160()})),older(2))")
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_b(c:pk_h({dummy_h160()}),sc:pk_k({dummy_pk()})))"
    )
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_b(c:pk_h({dummy_h160()}),sc:pk_k({dummy_pk()})))"
    )
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_n(c:pk_k({dummy_pk()}),c:pk_h({dummy_h160()})))"
    )
    roundtrip(f"or_b(c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}))")
    roundtrip(f"or_d(c:pk_k({dummy_pk()}),c:pk_k({dummy_pk()}))")
    roundtrip(
        f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:hash160({dummy_h160()}))))"
    )
    roundtrip(
        f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:sha256({dummy_h256()}))))"
    )
    roundtrip(f"or_i(and_v(vc:pk_h({dummy_h160()}),hash256({dummy_h256()})),older(20))")
    roundtrip(f"andor(c:pk_k({dummy_pk()}),older(25),c:pk_k({dummy_pk()}))")
    roundtrip(
        f"andor(c:pk_k({dummy_pk()}),or_i(and_v(vc:pk_h({dummy_h160()}),ripemd160({dummy_h160()})),older(35)),c:pk_k({dummy_pk()}))"
    )
    roundtrip(
        f"thresh(3,c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sdv:after(30))"
    )
    roundtrip(
        f"thresh(4,c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}))"
    )
    roundtrip(
        f"or_d(multi(1,{dummy_pk()}),or_b(multi(3,{dummy_pk()},{dummy_pk()},{dummy_pk()}),su:after(50)))"
    )
    roundtrip(f"uuj:and_v(v:multi(2,{dummy_pk()},{dummy_pk()}),after(10))")
    roundtrip(
        f"or_i(or_i(j:and_v(v:multi(2,{dummy_pk()},{dummy_pk()}),after(987)),0),0)"
    )
    roundtrip(
        f"or_b(or_i(n:multi(1,{dummy_pk()},{dummy_pk()}),0),a:or_i(0,older(1111)))"
    )
    roundtrip(f"llllllllllllllllllllllllllllll:pk({dummy_pk()})")


def test_compat_valid():
    """
    Valid samples from the C++ and Rust implementation. For now only checks MS
    string parsing and encoding to Script.
    """
    valid_samples = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "valid_samples.txt"
    )
    with open(valid_samples, "r") as f:
        for line in f:
            ms, hexscript = line.strip().split(" ")
            assert miniscript_from_str(ms).script.hex() == hexscript


def test_compat_invalid():
    invalid_samples = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "invalid_samples.txt"
    )
    with open(invalid_samples, "r") as f:
        for line in f:
            with pytest.raises(Exception):
                miniscript_from_str(line.strip())


def test_timelock_conflicts():
    # Absolute timelock simple conflicts
    assert miniscript_from_str("after(100)").no_timelock_mix
    assert miniscript_from_str("after(1000000000)").no_timelock_mix
    assert not miniscript_from_str(
        "and_b(after(100),a:after(1000000000))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_b(after(1000000000),a:after(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_v(v:after(100),after(1000000000))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_v(v:after(1000000000),after(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_n(dv:after(100),after(1000000000))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_n(dv:after(1000000000),after(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(dv:after(100),after(1000000000),after(1))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(dv:after(1000000000),after(100),after(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:after(100),after(1),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:after(1000000000),after(1000000000),after(1))"
    ).no_timelock_mix
    assert miniscript_from_str("or_b(dv:after(100),adv:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str("or_c(dv:after(100),v:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "or_c(dv:after(100),v:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "or_c(dv:after(1000000000),v:after(100))"
    ).no_timelock_mix
    assert miniscript_from_str("or_d(dv:after(100),after(1))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:after(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:after(1000000000),after(100))").no_timelock_mix
    assert miniscript_from_str("or_i(after(100),after(1))").no_timelock_mix
    assert miniscript_from_str("or_i(after(100),after(1000000004))").no_timelock_mix
    assert miniscript_from_str("or_i(after(1000000002),after(100))").no_timelock_mix
    assert miniscript_from_str("thresh(1,dv:after(100),adv:after(1))").no_timelock_mix
    assert miniscript_from_str("thresh(2,dv:after(100),adv:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "thresh(1,dv:after(1000000007),adv:after(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:after(1000000007),adv:after(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:after(12),adv:after(1000000007))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:after(12),adv:after(1000000007),adv:after(3))"
    ).no_timelock_mix

    # Relative timelock simple conflicts
    assert miniscript_from_str("older(100)").no_timelock_mix
    assert miniscript_from_str("older(4194304)").no_timelock_mix
    assert not miniscript_from_str("and_b(older(100),a:older(4194304))").no_timelock_mix
    assert not miniscript_from_str("and_b(older(4194304),a:older(100))").no_timelock_mix
    assert not miniscript_from_str("and_v(v:older(100),older(4194304))").no_timelock_mix
    assert not miniscript_from_str("and_v(v:older(4194304),older(100))").no_timelock_mix
    assert not miniscript_from_str(
        "and_n(dv:older(100),older(4194304))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_n(dv:older(4194304),older(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(dv:older(100),older(4194304),older(1))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(dv:older(4194304),older(100),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:older(100),older(1),older(4194304))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:older(4194304),older(4194304),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(1))").no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_c(dv:older(100),v:older(1))").no_timelock_mix
    assert miniscript_from_str("or_c(dv:older(100),v:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_c(dv:older(4194304),v:older(100))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:older(100),older(1))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:older(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:older(4194304),older(100))").no_timelock_mix
    assert miniscript_from_str("or_i(older(100),older(1))").no_timelock_mix
    assert miniscript_from_str("or_i(older(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_i(older(4194302),older(100))").no_timelock_mix
    assert miniscript_from_str("thresh(1,dv:older(100),adv:older(1))").no_timelock_mix
    assert miniscript_from_str("thresh(2,dv:older(100),adv:older(1))").no_timelock_mix
    assert miniscript_from_str(
        "thresh(1,dv:older(4194307),adv:older(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:older(4194307),adv:older(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:older(12),adv:older(4194307))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,dv:older(12),adv:older(4194307),adv:older(3))"
    ).no_timelock_mix

    # There is no mix across relative and absolute timelocks
    assert miniscript_from_str(
        "thresh(2,dv:older(12),adv:after(1000000000),adv:older(3))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "thresh(2,dv:after(12),adv:older(4194307),adv:after(3))"
    ).no_timelock_mix
    assert miniscript_from_str("or_i(older(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_i(older(4194302),after(100))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:older(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_d(dv:older(4194304),after(100))").no_timelock_mix
    assert miniscript_from_str(
        "or_c(dv:older(100),v:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str("or_c(dv:older(4194304),v:after(100))").no_timelock_mix
    assert miniscript_from_str("and_b(older(100),a:after(1000000000))").no_timelock_mix
    assert miniscript_from_str("and_b(older(4194304),a:after(100))").no_timelock_mix
    assert miniscript_from_str("and_v(v:after(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("and_v(v:older(4194304),after(100))").no_timelock_mix
    assert miniscript_from_str("and_n(dv:after(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str(
        "and_n(dv:older(4194304),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:older(100),after(1000000000),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:older(100),older(1),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(dv:older(4194304),after(4194304),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str("or_b(dv:after(100),adv:older(4194304))").no_timelock_mix
    assert miniscript_from_str(
        "or_b(dv:older(100),adv:after(1000000000))"
    ).no_timelock_mix

    # Some more complicated scenarii
    # These can be satisfied, but the first branch can never be part of the satisfaction
    assert not miniscript_from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:older(4)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:after(4)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)))"
    ).no_timelock_mix
    # These can be satisfied, but the second branch needs to always be part of the
    # satisfaction. They don't have the 'k' property as they certainly don't "match
    # the user expectation of the corresponding spending policy".
    assert not miniscript_from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:older(4)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)),a:and_b(pk({dummy_pk()}),sdv:older(15)))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:after(4)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)),a:and_b(pk({dummy_pk()}),sdv:after(15)))"
    ).no_timelock_mix
    # Two cases from the C++ unit tests
    assert not miniscript_from_str(
        "thresh(2,ltv:after(1000000000),altv:after(100),a:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(1000000000),altv:after(100))"
    ).no_timelock_mix
