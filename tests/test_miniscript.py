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
        f"thresh(3,c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}),sndv:after(30))"
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
            if line.startswith("#"):
                continue
            ms_str, hexscript = line.strip().split(" ")
            ms = miniscript_from_str(ms_str)
            assert ms.script.hex() == hexscript


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
        "and_n(ndv:after(100),after(1000000000))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_n(ndv:after(1000000000),after(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(ndv:after(100),after(1000000000),after(1))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(ndv:after(1000000000),after(100),after(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:after(100),after(1),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:after(1000000000),after(1000000000),after(1))"
    ).no_timelock_mix
    assert miniscript_from_str("or_b(dv:after(100),adv:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str("or_c(ndv:after(100),v:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "or_c(ndv:after(100),v:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "or_c(ndv:after(1000000000),v:after(100))"
    ).no_timelock_mix
    assert miniscript_from_str("or_d(ndv:after(100),after(1))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:after(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:after(1000000000),after(100))").no_timelock_mix
    assert miniscript_from_str("or_i(after(100),after(1))").no_timelock_mix
    assert miniscript_from_str("or_i(after(100),after(1000000004))").no_timelock_mix
    assert miniscript_from_str("or_i(after(1000000002),after(100))").no_timelock_mix
    assert miniscript_from_str("thresh(1,ndv:after(100),andv:after(1))").no_timelock_mix
    assert miniscript_from_str("thresh(2,ndv:after(100),andv:after(1))").no_timelock_mix
    assert miniscript_from_str(
        "thresh(1,ndv:after(1000000007),andv:after(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:after(1000000007),andv:after(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:after(12),andv:after(1000000007))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:after(12),andv:after(1000000007),andv:after(3))"
    ).no_timelock_mix

    # Relative timelock simple conflicts
    assert miniscript_from_str("older(100)").no_timelock_mix
    assert miniscript_from_str("older(4194304)").no_timelock_mix
    assert not miniscript_from_str("and_b(older(100),a:older(4194304))").no_timelock_mix
    assert not miniscript_from_str("and_b(older(4194304),a:older(100))").no_timelock_mix
    assert not miniscript_from_str("and_v(v:older(100),older(4194304))").no_timelock_mix
    assert not miniscript_from_str("and_v(v:older(4194304),older(100))").no_timelock_mix
    assert not miniscript_from_str(
        "and_n(ndv:older(100),older(4194304))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "and_n(ndv:older(4194304),older(100))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(ndv:older(100),older(4194304),older(1))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "andor(ndv:older(4194304),older(100),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:older(100),older(1),older(4194304))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:older(4194304),older(4194304),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(1))").no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_c(ndv:older(100),v:older(1))").no_timelock_mix
    assert miniscript_from_str("or_c(ndv:older(100),v:older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_c(ndv:older(4194304),v:older(100))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:older(100),older(1))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:older(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:older(4194304),older(100))").no_timelock_mix
    assert miniscript_from_str("or_i(older(100),older(1))").no_timelock_mix
    assert miniscript_from_str("or_i(older(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("or_i(older(4194302),older(100))").no_timelock_mix
    assert miniscript_from_str("thresh(1,ndv:older(100),andv:older(1))").no_timelock_mix
    assert miniscript_from_str("thresh(2,ndv:older(100),andv:older(1))").no_timelock_mix
    assert miniscript_from_str(
        "thresh(1,ndv:older(4194307),andv:older(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:older(4194307),andv:older(12))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:older(12),andv:older(4194307))"
    ).no_timelock_mix
    assert not miniscript_from_str(
        "thresh(2,ndv:older(12),andv:older(4194307),andv:older(3))"
    ).no_timelock_mix

    # There is no mix across relative and absolute timelocks
    assert miniscript_from_str(
        "thresh(2,ndv:older(12),andv:after(1000000000),andv:older(3))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "thresh(2,ndv:after(12),andv:older(4194307),andv:after(3))"
    ).no_timelock_mix
    assert miniscript_from_str("or_i(older(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_i(older(4194302),after(100))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:older(100),after(1000000000))").no_timelock_mix
    assert miniscript_from_str("or_d(ndv:older(4194304),after(100))").no_timelock_mix
    assert miniscript_from_str(
        "or_c(ndv:older(100),v:after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str("or_c(ndv:older(4194304),v:after(100))").no_timelock_mix
    assert miniscript_from_str("and_b(older(100),a:after(1000000000))").no_timelock_mix
    assert miniscript_from_str("and_b(older(4194304),a:after(100))").no_timelock_mix
    assert miniscript_from_str("and_v(v:after(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str("and_v(v:older(4194304),after(100))").no_timelock_mix
    assert miniscript_from_str("and_n(ndv:after(100),older(4194304))").no_timelock_mix
    assert miniscript_from_str(
        "and_n(ndv:older(4194304),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:older(100),after(1000000000),older(1))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:older(100),older(1),after(1000000000))"
    ).no_timelock_mix
    assert miniscript_from_str(
        "andor(ndv:older(4194304),after(4194304),older(1))"
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


def test_satisfaction_cost():
    """Test the calculation of the satisfaction cost in resources (number of ops and stack size)."""
    # Vectors from the C++ implem.
    vectors = [
        # Miniscript, OPs cost, stack size (without the P2WSH script push)
        ["lltvln:after(1231488000)", 12, 3],
        [
            "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
            14,
            5,
        ],
        [
            "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))",
            14,
            5,
        ],
        ["j:and_v(vdv:after(1567547623),older(2016))", 11, 1],
        [
            "t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))",
            12,
            3,
        ],
        [
            "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))",
            13,
            5,
        ],
        [
            "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))",
            15,
            7,
        ],
        [
            "or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))",
            16,
            1,
        ],
        [
            "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))",
            11,
            5,
        ],
        [
            "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))",
            14,
            4,
        ],
        [
            "and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))",
            12,
            1,
        ],
        [
            "j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))",
            16,
            2,
        ],
        [
            "and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))",
            15,
            2,
        ],
        [
            "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
            13,
            6,
        ],
        [
            "and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))",
            14,
            2,
        ],
        [
            "or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))",
            15,
            2,
        ],
        [
            "c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
            8,
            2,
        ],
        [
            "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
            10,
            5,
        ],
        [
            "and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))",
            14,
            2,
        ],
        [
            "andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))",
            20,
            2,
        ],
        [
            "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))",
            10,
            2,
        ],
        [
            "thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))",
            18,
            4,
        ],
        [
            "and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))",
            13,
            3,
        ],
        [
            "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))",
            12,
            2,
        ],
        [
            "c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))",
            12,
            3,
        ],
        [
            "or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))",
            13,
            3,
        ],
        [
            "c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))",
            18,
            3,
        ],
        [
            "c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))",
            23,
            4,
        ],
        [
            "c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))",
            17,
            5,
        ],
        [
            "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(1000000000),altv:after(100))",
            18,
            3,
        ],
        [
            "thresh(2,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),ac:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),altv:after(1000000000),altv:after(100))",
            22,
            4,
        ],
    ]

    for ms_str, op_cost, sat_cost in vectors:
        ms = miniscript_from_str(ms_str)
        assert ms.exec_info.ops_count == op_cost
        assert ms.exec_info.sat_elems == sat_cost
