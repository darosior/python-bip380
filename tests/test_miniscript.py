import hashlib
import os
import pytest

from bip32 import BIP32
from miniscript.miniscript import Node


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
    node_a = Node.from_desc(ms_str)
    node_b = Node.from_script(node_a.script)

    assert node_a.script == node_b.script
    assert str(node_a.p) == str(node_b.p)
    assert node_a.t == node_b.t

    return node_b


def test_simple_sanity_checks():
    """Some quick and basic sanity checks of the implem. The place to add new findings."""

    not_aliased = Node.from_desc(
        "and_v(vc:pk_k(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),c:pk_k(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))"
    )
    aliased = Node.from_desc(
        "and_v(v:pk(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),pk(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))"
    )
    assert aliased.script == not_aliased.script

    assert roundtrip("older(1)")._delay == 1
    assert roundtrip("older(255)")._delay == 255
    assert roundtrip("older(16407)")._delay == 16407
    assert roundtrip("older(1621038656)")._delay == 1621038656
    assert roundtrip("after(1)")._time == 1
    assert roundtrip("after(255)")._time == 255
    assert roundtrip("after(16407)")._time == 16407
    assert roundtrip("after(1621038656)")._time == 1621038656
    # CSV with a negative value
    with pytest.raises(Exception):
        Node.from_script(b"\x86\x92\xB2")
    # CLTV with a negative value
    with pytest.raises(Exception):
        Node.from_script(b"\x86\x92\xB1")

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
    # FIXME: they don't roundtrip
    # roundtrip(f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:hash160({dummy_h160()}))))")
    # roundtrip(f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:sha256({dummy_h256()}))))")
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
    # FIXME: they don't roundtrip
    # roundtrip(f"uuj:and_v(v:multi(2,{dummy_pk()},{dummy_pk()}),after(10))")
    # roundtrip(f"or_i(or_i(j:and_v(v:multi(2,{dummy_pk()},{dummy_pk()}),after(987)),0),0)")
    # roundtrip(f"or_b(or_i(n:multi(1,{dummy_pk()},{dummy_pk()}),0),a:or_i(0,older(1111)))")


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
            assert Node.from_desc(ms).script.hex() == hexscript


def test_compat_invalid():
    invalid_samples = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "invalid_samples.txt"
    )
    with open(invalid_samples, "r") as f:
        for line in f:
            print(line)
            with pytest.raises(Exception):
                Node.from_desc(line.strip())
