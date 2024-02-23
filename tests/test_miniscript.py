import coincurve
import hashlib
import os
import pytest

from bip32 import BIP32
from bitcointx.core import (
    CMutableTxIn,
    CMutableTxOut,
    CMutableTransaction,
    COutPoint,
)
from bitcointx.core.bitcoinconsensus import (
    ConsensusVerifyScript,
    BITCOINCONSENSUS_ACCEPTED_FLAGS,
)
from bitcointx.core.script import (
    CScript as CScriptBitcoinTx,
    CScriptWitness,
    RawBitcoinSignatureHash,
    SIGVERSION_WITNESS_V0,
)
from itertools import chain
from bip380.key import DescriptorKey
from bip380.miniscript import fragments, SatisfactionMaterial
from bip380.miniscript.errors import MiniscriptMalformed
from bip380.utils.script import (
    CScript,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_EQUAL,
    OP_NUMEQUAL,
)


def dummy_pk():
    return BIP32.from_seed(os.urandom(32)).get_pubkey_from_path("m").hex()


def dummy_h256():
    return os.urandom(32).hex()


def dummy_h160():
    return os.urandom(20).hex()


def ripemd160(data):
    return hashlib.new("ripemd160", data).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(hex):
    data = bytes.fromhex(hex)
    return ripemd160(sha256(data))


def hash256(data):
    return sha256(sha256(data))


def roundtrip(ms_str, is_taproot=False):
    """Test we can parse to and from Script and string representation.

    Note that the Script representation does not necessarily roundtrip. However
    it must be deterministic.
    """
    node_a = fragments.Node.from_str(ms_str, is_taproot)
    node_b = fragments.Node.from_script(node_a.script, is_taproot)

    assert node_b.script == fragments.Node.from_script(node_b.script, is_taproot).script
    assert str(node_b) == str(fragments.Node.from_str(str(node_b), is_taproot))

    return node_b


def test_simple_sanity_checks():
    """Some quick and basic sanity checks of the implem. The place to add new findings."""

    not_aliased = fragments.Node.from_str(
        "and_v(vc:pk_k(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),c:pk_k(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))"
    )
    aliased = fragments.Node.from_str(
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
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(CScript(b"\x86\x92\xB2"))
    # CLTV with a negative value
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(CScript(b"\x86\x92\xB1"))

    roundtrip(f"pk({dummy_pk()})")
    roundtrip(f"pk_k({dummy_pk()})")
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
    roundtrip(f"and_v(and_v(vc:pk_k({dummy_pk()}),vc:pk_k({dummy_pk()})),older(2))")
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_b(c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()})))"
    )
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_b(c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()})))"
    )
    roundtrip(
        f"or_b(c:pk_k({dummy_pk()}),a:and_n(c:pk_k({dummy_pk()}),c:pk_k({dummy_pk()})))"
    )
    roundtrip(f"or_b(c:pk_k({dummy_pk()}),sc:pk_k({dummy_pk()}))")
    roundtrip(f"or_d(c:pk_k({dummy_pk()}),c:pk_k({dummy_pk()}))")
    roundtrip(
        f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:hash160({dummy_h160()}))))"
    )
    roundtrip(
        f"t:or_c(c:pk_k({dummy_pk()}),and_v(vc:pk_k({dummy_pk()}),or_c(c:pk_k({dummy_pk()}),v:sha256({dummy_h256()}))))"
    )
    roundtrip(f"or_i(and_v(vc:pk_k({dummy_pk()}),hash256({dummy_h256()})),older(20))")
    roundtrip(f"andor(c:pk_k({dummy_pk()}),older(25),c:pk_k({dummy_pk()}))")
    roundtrip(
        f"andor(c:pk_k({dummy_pk()}),or_i(and_v(vc:pk_k({dummy_pk()}),ripemd160({dummy_h160()})),older(35)),c:pk_k({dummy_pk()}))"
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
            ms = fragments.Node.from_str(ms_str)
            assert ms.script.hex() == hexscript
            ms.satisfaction(SatisfactionMaterial())
            ms.dissatisfaction()


def test_compat_invalid():
    invalid_samples = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "invalid_samples.txt"
    )
    with open(invalid_samples, "r") as f:
        for line in f:
            with pytest.raises(Exception):
                fragments.Node.from_str(line.strip())


def test_timelock_conflicts():
    # Absolute timelock simple conflicts
    assert fragments.Node.from_str("after(100)").no_timelock_mix
    assert fragments.Node.from_str("after(1000000000)").no_timelock_mix
    assert not fragments.Node.from_str(
        "and_b(after(100),a:after(1000000000))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_b(after(1000000000),a:after(100))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_v(v:after(100),after(1000000000))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_v(v:after(1000000000),after(100))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_n(ndv:after(100),after(1000000000))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_n(ndv:after(1000000000),after(100))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "andor(ndv:after(100),after(1000000000),after(1))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "andor(ndv:after(1000000000),after(100),after(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:after(100),after(1),after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:after(1000000000),after(1000000000),after(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_b(dv:after(100),adv:after(1))").no_timelock_mix
    assert fragments.Node.from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "or_b(dv:after(100),adv:after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_c(ndv:after(100),v:after(1))").no_timelock_mix
    assert fragments.Node.from_str(
        "or_c(ndv:after(100),v:after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "or_c(ndv:after(1000000000),v:after(100))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:after(100),after(1))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:after(100),after(1000000000))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:after(1000000000),after(100))").no_timelock_mix
    assert fragments.Node.from_str("or_i(after(100),after(1))").no_timelock_mix
    assert fragments.Node.from_str("or_i(after(100),after(1000000004))").no_timelock_mix
    assert fragments.Node.from_str("or_i(after(1000000002),after(100))").no_timelock_mix
    assert fragments.Node.from_str("thresh(1,ndv:after(100),andv:after(1))").no_timelock_mix
    assert fragments.Node.from_str("thresh(2,ndv:after(100),andv:after(1))").no_timelock_mix
    assert fragments.Node.from_str(
        "thresh(1,ndv:after(1000000007),andv:after(12))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:after(1000000007),andv:after(12))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:after(12),andv:after(1000000007))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:after(12),andv:after(1000000007),andv:after(3))"
    ).no_timelock_mix

    # Relative timelock simple conflicts
    assert fragments.Node.from_str("older(100)").no_timelock_mix
    assert fragments.Node.from_str("older(4194304)").no_timelock_mix
    assert not fragments.Node.from_str("and_b(older(100),a:older(4194304))").no_timelock_mix
    assert not fragments.Node.from_str("and_b(older(4194304),a:older(100))").no_timelock_mix
    assert not fragments.Node.from_str("and_v(v:older(100),older(4194304))").no_timelock_mix
    assert not fragments.Node.from_str("and_v(v:older(4194304),older(100))").no_timelock_mix
    assert not fragments.Node.from_str(
        "and_n(ndv:older(100),older(4194304))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "and_n(ndv:older(4194304),older(100))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "andor(ndv:older(100),older(4194304),older(1))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "andor(ndv:older(4194304),older(100),older(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:older(100),older(1),older(4194304))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:older(4194304),older(4194304),older(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_b(dv:older(100),adv:older(1))").no_timelock_mix
    assert fragments.Node.from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("or_b(dv:older(100),adv:older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("or_c(ndv:older(100),v:older(1))").no_timelock_mix
    assert fragments.Node.from_str("or_c(ndv:older(100),v:older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("or_c(ndv:older(4194304),v:older(100))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:older(100),older(1))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:older(100),older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:older(4194304),older(100))").no_timelock_mix
    assert fragments.Node.from_str("or_i(older(100),older(1))").no_timelock_mix
    assert fragments.Node.from_str("or_i(older(100),older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("or_i(older(4194302),older(100))").no_timelock_mix
    assert fragments.Node.from_str("thresh(1,ndv:older(100),andv:older(1))").no_timelock_mix
    assert fragments.Node.from_str("thresh(2,ndv:older(100),andv:older(1))").no_timelock_mix
    assert fragments.Node.from_str(
        "thresh(1,ndv:older(4194307),andv:older(12))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:older(4194307),andv:older(12))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:older(12),andv:older(4194307))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        "thresh(2,ndv:older(12),andv:older(4194307),andv:older(3))"
    ).no_timelock_mix

    # There is no mix across relative and absolute timelocks
    assert fragments.Node.from_str(
        "thresh(2,ndv:older(12),andv:after(1000000000),andv:older(3))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "thresh(2,ndv:after(12),andv:older(4194307),andv:after(3))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_i(older(100),after(1000000000))").no_timelock_mix
    assert fragments.Node.from_str("or_i(older(4194302),after(100))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:older(100),after(1000000000))").no_timelock_mix
    assert fragments.Node.from_str("or_d(ndv:older(4194304),after(100))").no_timelock_mix
    assert fragments.Node.from_str(
        "or_c(ndv:older(100),v:after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_c(ndv:older(4194304),v:after(100))").no_timelock_mix
    assert fragments.Node.from_str("and_b(older(100),a:after(1000000000))").no_timelock_mix
    assert fragments.Node.from_str("and_b(older(4194304),a:after(100))").no_timelock_mix
    assert fragments.Node.from_str("and_v(v:after(100),older(4194304))").no_timelock_mix
    assert fragments.Node.from_str("and_v(v:older(4194304),after(100))").no_timelock_mix
    assert fragments.Node.from_str("and_n(ndv:after(100),older(4194304))").no_timelock_mix
    assert fragments.Node.from_str(
        "and_n(ndv:older(4194304),after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:older(100),after(1000000000),older(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:older(100),older(1),after(1000000000))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
        "andor(ndv:older(4194304),after(4194304),older(1))"
    ).no_timelock_mix
    assert fragments.Node.from_str("or_b(dv:after(100),adv:older(4194304))").no_timelock_mix
    assert fragments.Node.from_str(
        "or_b(dv:older(100),adv:after(1000000000))"
    ).no_timelock_mix

    # Some more complicated scenarii
    # These can be satisfied, but the first branch can never be part of the satisfaction
    assert not fragments.Node.from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:older(4)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:after(4)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)))"
    ).no_timelock_mix
    # These can be satisfied, but the second branch needs to always be part of the
    # satisfaction. They don't have the 'k' property as they certainly don't "match
    # the user expectation of the corresponding spending policy".
    assert not fragments.Node.from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:older(4)),a:and_b(pk({dummy_pk()}),sdv:older(4194304)),a:and_b(pk({dummy_pk()}),sdv:older(15)))"
    ).no_timelock_mix
    assert not fragments.Node.from_str(
        f"thresh(2,and_b(pk({dummy_pk()}),sdv:after(4)),a:and_b(pk({dummy_pk()}),sdv:after(1000000000)),a:and_b(pk({dummy_pk()}),sdv:after(15)))"
    ).no_timelock_mix
    # Two cases from the C++ unit tests
    assert not fragments.Node.from_str(
        "thresh(2,ltv:after(1000000000),altv:after(100),a:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))"
    ).no_timelock_mix
    assert fragments.Node.from_str(
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
        ms = fragments.Node.from_str(ms_str)
        assert ms.exec_info.ops_count == op_cost
        assert ms.exec_info.sat_elems == sat_cost


def test_satisfy_simple_combs():
    """Test the satisfaction logic of most fragments and simple combinations of them."""
    hd = BIP32.from_seed(os.urandom(32))
    keypairs = {
        hd.get_privkey_from_path([i]): hd.get_pubkey_from_path([i]) for i in range(20)
    }

    timelock = 11
    preimage = bytes(32)
    keys = [DescriptorKey(k) for k in keypairs.values()]
    dummy_sigs = []
    for privkey, pubkey in keypairs.items():
        dummy_sigs.append(
            (pubkey, coincurve.PrivateKey(privkey).sign(bytes(32), hasher=None))
        )
    sat_material = SatisfactionMaterial()
    for h_func, digest in [
        (fragments.Sha256, sha256(preimage)),
        (fragments.Hash256, hash256(preimage)),
        (fragments.Ripemd160, ripemd160(preimage)),
        (fragments.Hash160, hash160(preimage.hex())),
    ]:
        for tl_func in [fragments.Older, fragments.After]:
            for multi_threshold in range(1, 21):
                h_frag = h_func(digest)
                # Without the preimage in the material, it can't satisfy it
                assert h_frag.satisfaction(sat_material).witness is None
                # Now if we set it it'll be able to
                sat_material.preimages[h_frag.digest] = preimage
                assert h_frag.satisfaction(sat_material).witness == [preimage]
                or_frag = fragments.OrB(
                    h_frag,
                    fragments.WrapS(
                        fragments.WrapD(fragments.WrapV(fragments.Older(timelock)), is_taproot=False)
                    ),
                )
                # Without the ability to satisfy the timelock, it'll choose the hash path.
                assert or_frag.satisfaction(sat_material).witness == [b"", preimage]
                # But if we tell it the timelock can be satisfied it'll still not choose that since
                # dissatisfying a hash is malleable.
                if tl_func is fragments.Older:
                    sat_material.max_sequence = timelock
                if tl_func is fragments.After:
                    sat_material.max_sequence = timelock
                assert or_frag.satisfaction(sat_material).witness == [b"", preimage]
                # Now if we make it non-malleably dissatisfiable, it'll choose the timelock path as it's cheaper.
                h_frag = fragments.WrapJ(h_frag)
                or_frag = fragments.OrB(
                    h_frag,
                    fragments.WrapS(
                        fragments.WrapD(fragments.WrapV(fragments.Older(timelock)), is_taproot=False)
                    ),
                )
                assert or_frag.satisfaction(sat_material).witness == [b"\x01", b""]
                # It won't be able to satisfy the and_v() without enough sigs
                frag = fragments.AndV(
                    fragments.WrapV(fragments.Multi(multi_threshold, keys)),
                    or_frag,
                )
                assert frag.satisfaction(sat_material).witness is None
                for pubkey, sig in dummy_sigs[: multi_threshold - 1]:
                    sat_material.signatures[pubkey] = sig
                assert frag.satisfaction(sat_material).witness is None
                # Just enough sigs is sufficient
                pubkey, sig = dummy_sigs[multi_threshold - 1]
                sat_material.signatures[pubkey] = sig
                assert (
                    frag.satisfaction(sat_material).witness
                    == [
                        b"\x01",
                        b"",
                        b"",
                    ]
                    + list(sat_material.signatures.values())
                )
                # Now if we remove the timelocks it'll get back to satisfy using the hash preimage
                sat_material.max_sequence = 0
                sat_material.max_timelock = 0
                assert (
                    frag.satisfaction(sat_material).witness
                    == [
                        b"",
                        preimage,
                        b"",
                    ]
                    + list(sat_material.signatures.values())
                )
                sat_material.clear()

    sat_material = SatisfactionMaterial()
    pk_frag_a = fragments.Pk(keys[0])
    pk_frag_b = fragments.Pk(keys[1])
    pkh_frag = fragments.Pkh(keys[2])
    or_i_frag = fragments.OrI(pk_frag_a, pkh_frag)
    # No signature, no satisfaction.
    assert or_i_frag.satisfaction(sat_material).witness is None
    # Need only one side for having a satisfaction
    pubkey, sig = dummy_sigs[2]
    sat_material.signatures[pubkey] = sig
    assert or_i_frag.satisfaction(sat_material).witness == [sig, pubkey, b""]
    # However if the pk() satisfaction is also available, it'll choose it as it's smaller
    pubkey, sig = dummy_sigs[0]
    sat_material.signatures[pubkey] = sig
    assert or_i_frag.satisfaction(sat_material).witness == [sig, b"\x01"]
    # If we add a requirement for another, it'll fail without the sig and succeed with it
    and_b_frag = fragments.AndB(
        fragments.WrapC(or_i_frag), fragments.WrapA(fragments.WrapC(pk_frag_b))
    )
    assert and_b_frag.satisfaction(sat_material).witness is None
    pubkey2, sig2 = dummy_sigs[1]
    sat_material.signatures[pubkey2] = sig2
    assert and_b_frag.satisfaction(sat_material).witness == [
        sig2,
        sig,
        b"\x01",
    ]
    sat_material.clear()

    check_pk_a = fragments.WrapC(pk_frag_a)
    check_pk_b = fragments.WrapC(pk_frag_b)
    or_c_frag = fragments.OrC(check_pk_a, fragments.WrapV(check_pk_b))
    assert or_c_frag.satisfaction(sat_material).witness is None
    pubkey, sig = dummy_sigs[0]
    sat_material.signatures[pubkey] = sig
    assert or_c_frag.satisfaction(sat_material).witness == [sig]
    pubkey2, sig2 = dummy_sigs[1]
    sat_material.signatures[pubkey2] = sig2
    assert or_c_frag.satisfaction(sat_material).witness == [sig]
    del sat_material.signatures[pubkey]
    assert or_c_frag.satisfaction(sat_material).witness == [sig2, b""]
    sat_material.clear()

    check_pkh_c = fragments.WrapC(pkh_frag)
    check_pk_d = fragments.WrapC(fragments.Pk(keys[3]))
    check_pk_e = fragments.WrapC(fragments.Pk(keys[4]))
    or_d_frag = fragments.OrD(check_pk_a, check_pk_b)
    andor_frag = fragments.AndOr(
        check_pkh_c, fragments.WrapN(fragments.After(1_000)), check_pk_d
    )
    thresh_frag = fragments.Thresh(
        1,
        [
            or_d_frag,
            fragments.WrapA(andor_frag),
            fragments.WrapS(check_pk_e),
        ],
    )
    assert thresh_frag.satisfaction(sat_material).witness is None
    # Add the sig to satisfy the last sub
    pubkey_e, sig_e = dummy_sigs[4]
    sat_material.signatures[pubkey_e] = sig_e
    assert thresh_frag.satisfaction(sat_material).witness == [
        sig_e,  # pk E
        b"",  # pk D
        b"",  # pkh C
        pkh_frag.pubkey.bytes(),  # pkh C
        b"",  # pk B
        b"",  # pk A
    ]
    # With a larger threshold, doesn't work
    thresh_frag = fragments.Thresh(
        2,
        [
            or_d_frag,
            fragments.WrapA(andor_frag),
            fragments.WrapS(check_pk_e),
        ],
    )
    assert thresh_frag.satisfaction(sat_material).witness is None
    # Satisfy the first sub, in the two available ways
    pubkey_a, sig_a = dummy_sigs[0]
    sat_material.signatures[pubkey_a] = sig_a
    assert thresh_frag.satisfaction(sat_material).witness == [
        sig_e,  # pk E
        b"",  # pk D
        b"",  # pkh C
        pkh_frag.pubkey.bytes(),  # pkh C
        sig_a,  # pk A
    ]
    pubkey_b, sig_b = dummy_sigs[1]
    sat_material.signatures[pubkey_b] = sig_b
    del sat_material.signatures[pubkey_a]
    assert thresh_frag.satisfaction(sat_material).witness == [
        sig_e,  # pk E
        b"",  # pk D
        b"",  # pkh C
        pkh_frag.pubkey.bytes(),  # pkh C
        sig_b,  # pk B
        b"",  # pk A
    ]
    # Now get the threshold at a maximum, we need to satisfy the andor()
    thresh_frag = fragments.Thresh(
        3,
        [
            or_d_frag,
            fragments.WrapA(andor_frag),
            fragments.WrapS(check_pk_e),
        ],
    )
    assert thresh_frag.satisfaction(sat_material).witness is None
    pubkey_d, sig_d = dummy_sigs[3]
    sat_material.signatures[pubkey_d] = sig_d
    assert thresh_frag.satisfaction(sat_material).witness == [
        sig_e,  # pk E
        sig_d,  # pk D
        b"",  # pkh C
        pkh_frag.pubkey.bytes(),  # pkh C
        sig_b,  # pk B
        b"",  # pk A
    ]
    del sat_material.signatures[pubkey_d]
    pubkey_c, sig_c = dummy_sigs[2]
    sat_material.signatures[pubkey_c] = sig_c
    assert thresh_frag.satisfaction(sat_material).witness is None
    sat_material.max_lock_time = 1_000
    assert thresh_frag.satisfaction(sat_material).witness == [
        sig_e,  # pk E
        sig_c,  # pkh C
        pubkey_c,  # pkh C
        sig_b,  # pk B
        b"",  # pk A
    ]


def sat_test(
    fragment,
    keypairs={},
    preimages={},
    max_sequence=0,
    max_lock_time=0,
    malleable=False,
):
    """Test a fragment's satisfaction against libbitcoinconsensus."""
    amount = 10_000
    txid = bytes.fromhex(
        "652c60ec08280356e8c78be9bf4d44276acef3189ba8223e426b757aeabd66ad"
    )

    # Create a P2WSH scriptPubKey, and a dummy transaction spending it
    script_pubkey = CScriptBitcoinTx([0, sha256(fragment.script)])
    txin_b = CMutableTxIn(COutPoint(txid, 0), nSequence=max_sequence)
    txout_b = CMutableTxOut(amount - 1_000, CScript([0, sha256(fragment.script)]))
    tx_b = CMutableTransaction([txin_b], [txout_b], nLockTime=max_lock_time)

    # Now populate the "signing data". Tell the satisfier about the available timelocks
    # and signatures. Since we'll check them, produce valid sigs for the dummy tx.
    sat_material = SatisfactionMaterial(
        preimages=preimages, max_sequence=max_sequence, max_lock_time=max_lock_time
    )
    sighash = RawBitcoinSignatureHash(
        script=fragment.script,
        txTo=tx_b,
        inIdx=0,
        hashtype=1,  # SIGHASH_ALL
        amount=amount,
        sigversion=SIGVERSION_WITNESS_V0,
    )[0]
    for pubkey, privkey in keypairs.items():
        sig = coincurve.PrivateKey(privkey).sign(sighash, hasher=None)
        sat_material.signatures[pubkey] = sig + b"\x01"  # SIGHASH_ALL
    if malleable:
        witness_stack = CScriptWitness(
            fragment.satisfaction(sat_material).witness + [fragment.script]
        )
    else:
        witness_stack = CScriptWitness(
            fragment.satisfy(sat_material) + [fragment.script]
        )
    # VerifyScript might be able to debug some very simple scripts, but is buggy and
    # outdated (a failing CHECKSIG doesn't return the empty vector, no implementation
    # of CSV and CLTV, and more that i didn't bother to trace down) so it makes it hard
    # for anything that is non-trivial. TODO: write our own interpreter w/ the OPs used
    # by Miniscript.
    # from bitcointx.core.scripteval import VerifyScript
    # VerifyScript(
    # scriptSig=txin_b.scriptSig,
    # scriptPubKey=txout_a.scriptPubKey,
    # txTo=tx_b,
    # inIdx=0,
    # amount=amount,
    # witness=witness_stack,
    # )

    # Finally check it against libbitcoinconsensus. Note this is missing Taproot's flags
    # but we don't care as we only support P2WSH for now.
    ConsensusVerifyScript(
        scriptSig=txin_b.scriptSig,
        scriptPubKey=script_pubkey,
        txTo=tx_b,
        inIdx=0,
        amount=amount,
        witness=witness_stack,
        flags=BITCOINCONSENSUS_ACCEPTED_FLAGS,
    )
    sat_material.clear()


def test_satisfaction_validity():
    """Test the validity of various fragments' satisfaction against libbitcoinconsensus"""
    hd = BIP32.from_seed(os.urandom(32))
    keypairs = {
        hd.get_pubkey_from_path([i]): hd.get_privkey_from_path([i]) for i in range(20)
    }
    pubkeys = list(keypairs.keys())

    sat_test(fragments.Just1(), malleable=True)

    pk_frag = fragments.WrapC(fragments.Pk(DescriptorKey(pubkeys[0])))
    pk_keypairs = {pubkeys[0]: keypairs[pubkeys[0]]}
    sat_test(
        pk_frag,
        keypairs=pk_keypairs,
    )

    pkh_frag = fragments.WrapC(fragments.Pkh(DescriptorKey(pubkeys[1])))
    pkh_keypairs = {pubkeys[1]: keypairs[pubkeys[1]]}
    sat_test(
        pkh_frag,
        keypairs=pkh_keypairs,
    )

    older_frag = fragments.Older(2)
    sat_test(older_frag, max_sequence=2, malleable=True)

    after_frag = fragments.After(2)
    sat_test(after_frag, max_lock_time=2, malleable=True)

    multi_keys, multi_keypairs = [], {}
    for n in range(1, 21):
        multi_keys.append(DescriptorKey(pubkeys[n - 1]))
        multi_keypairs[pubkeys[n - 1]] = keypairs[pubkeys[n - 1]]
        for m in range(1, n):
            sat_test(
                fragments.Multi(m, multi_keys),
                keypairs=multi_keypairs,
            )

    andv_frag = fragments.AndV(fragments.WrapV(pk_frag), pkh_frag)
    andv_keypairs = dict(
        chain.from_iterable(d.items() for d in [pk_keypairs, pkh_keypairs])
    )
    sat_test(andv_frag, keypairs=andv_keypairs)

    multi_keys = [DescriptorKey(key) for key in pubkeys[1:3]]
    and_b_keypairs = {pub: keypairs[pub] for pub in pubkeys[:2]}
    and_b_frag = fragments.AndB(
        pk_frag,
        fragments.WrapA(fragments.Multi(1, multi_keys)),
    )
    sat_test(
        and_b_frag,
        keypairs=and_b_keypairs,
    )

    or_b_frag = fragments.OrB(
        pk_frag,
        fragments.WrapA(fragments.Multi(1, multi_keys)),
    )
    or_b_keypairs = {pub: keypairs[pub] for pub in pubkeys[:1]}
    sat_test(
        or_b_frag,
        keypairs=or_b_keypairs,
    )
    or_b_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:2]}
    sat_test(
        or_b_frag,
        keypairs=or_b_keypairs,
    )
    or_b_keypairs = {pub: keypairs[pub] for pub in pubkeys[2:3]}
    sat_test(
        or_b_frag,
        keypairs=or_b_keypairs,
    )

    or_c_frag = fragments.OrC(pk_frag, fragments.WrapV(pkh_frag))
    or_c_keypairs = {pub: keypairs[pub] for pub in pubkeys[:1]}
    sat_test(
        fragments.WrapT(or_c_frag),
        keypairs=or_c_keypairs,
    )
    or_c_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:2]}
    sat_test(
        fragments.WrapT(or_c_frag),
        keypairs=or_c_keypairs,
    )

    or_d_frag = fragments.OrD(pk_frag, pkh_frag)
    or_d_keypairs = {pub: keypairs[pub] for pub in pubkeys[:1]}
    sat_test(
        or_d_frag,
        keypairs=or_d_keypairs,
    )
    or_d_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:2]}
    sat_test(
        or_d_frag,
        keypairs=or_d_keypairs,
    )

    multi_keys = [DescriptorKey(key) for key in pubkeys[2:5]]
    multi_frag = fragments.Multi(2, multi_keys)
    or_i_frag = fragments.OrI(multi_frag, pkh_frag)
    or_i_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:2]}
    sat_test(
        or_i_frag,
        keypairs=or_i_keypairs,
    )
    or_i_keypairs = {pub: keypairs[pub] for pub in pubkeys[2:4]}
    sat_test(
        or_i_frag,
        keypairs=or_i_keypairs,
    )

    andor_frag = fragments.AndOr(pk_frag, pkh_frag, multi_frag)
    andor_keypairs = {pub: keypairs[pub] for pub in pubkeys[0:2]}
    sat_test(
        andor_frag,
        keypairs=andor_keypairs,
    )
    andor_keypairs = {pub: keypairs[pub] for pub in pubkeys[2:4]}
    sat_test(
        andor_frag,
        keypairs=andor_keypairs,
    )
    andor_keypairs = {pub: keypairs[pub] for pub in pubkeys[3:5]}
    sat_test(
        andor_frag,
        keypairs=andor_keypairs,
    )

    # A CMS made verify, and back Wdu, for the purpose of exercising various
    # fragments.
    convoluted_cms = fragments.WrapA(
        fragments.AndB(
            fragments.WrapU(fragments.WrapT(fragments.WrapV(multi_frag))),
            fragments.WrapA(fragments.WrapL(fragments.Just1())),
        ),
    )
    thresh_frag = fragments.Thresh(
        1, [pkh_frag, fragments.WrapS(pk_frag), convoluted_cms]
    )
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[0:1]}
    sat_test(thresh_frag, keypairs=thresh_keypairs)
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:2]}
    sat_test(thresh_frag, keypairs=thresh_keypairs)
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[3:5]}
    sat_test(thresh_frag, keypairs=thresh_keypairs)
    thresh_frag2 = fragments.Thresh(
        2, [pkh_frag, fragments.WrapS(pk_frag), convoluted_cms]
    )
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[0:2]}
    sat_test(thresh_frag2, keypairs=thresh_keypairs)
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[1:4]}
    sat_test(thresh_frag2, keypairs=thresh_keypairs)
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[:1] + pubkeys[2:4]}
    sat_test(thresh_frag2, keypairs=thresh_keypairs)
    thresh_frag = fragments.Thresh(
        3, [pkh_frag, fragments.WrapS(pk_frag), convoluted_cms]
    )
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[:4]}
    sat_test(thresh_frag, keypairs=thresh_keypairs)
    thresh_keypairs = {pub: keypairs[pub] for pub in pubkeys[:3] + pubkeys[4:]}
    sat_test(thresh_frag, keypairs=thresh_keypairs)

    preimage = os.urandom(32)
    for h_frag, digest in [
        (fragments.Sha256, sha256(preimage)),
        (fragments.Hash256, hash256(preimage)),
        (fragments.Ripemd160, ripemd160(preimage)),
        (fragments.Hash160, hash160(preimage.hex())),
    ]:
        andv_frag = fragments.AndV(fragments.WrapV(pk_frag), h_frag(digest))
        sat_test(andv_frag, keypairs=pk_keypairs, preimages={digest: preimage})


def test_multi_is_expressive():
    frag = fragments.Node.from_str(f"or_b(pk({dummy_pk()}),a:multi(1,{dummy_pk()},{dummy_pk()}))")
    assert frag.is_nonmalleable

def test_multi_a():

    # Get a raw x-only public key
    def pk():
        return bytes.fromhex(dummy_pk())[1:]

    # Make sure we roundtrip under various conditions.
    roundtrip(f"multi_a(1,{pk().hex()})", is_taproot=True)
    roundtrip(f"multi_a(2,{pk().hex()},{pk().hex()})", is_taproot=True)
    roundtrip(f"multi_a(2,{pk().hex()},{pk().hex()},{pk().hex()})", is_taproot=True)
    roundtrip(f"multi_a(1,{pk().hex()},{pk().hex()},{pk().hex()})", is_taproot=True)
    ms_str = "multi_a(42,"
    for i in range(999):
        ms_str += pk().hex()
        if i != 998:
            ms_str += ","
    ms_str += ")"
    roundtrip(ms_str, is_taproot=True)

    # Make sure we detect some pathological cases, especially when parsing from Script.
    with pytest.raises(AssertionError):
        fragments.Node.from_str(f"multi_a(2,{pk().hex()})", is_taproot=True)
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(CScript([pk(), OP_CHECKSIGADD, 1, OP_NUMEQUAL]), is_taproot=True)
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(
            CScript([pk(), OP_CHECKSIG, pk(), OP_CHECKSIG, 1, OP_NUMEQUAL]), is_taproot=True
        )
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(
            CScript([pk(), OP_CHECKSIGADD, pk(), OP_CHECKSIG, 1, OP_NUMEQUAL]), is_taproot=True
        )
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(
            CScript([pk(), OP_CHECKSIG, pk(), OP_CHECKSIGADD, 1, OP_EQUAL]), is_taproot=True
        )
    with pytest.raises(MiniscriptMalformed):
        fragments.Node.from_script(
            CScript(
                [
                    pk(),
                    OP_CHECKSIG,
                    b"\x02" + bytes(31) + b"\x01",
                    OP_CHECKSIGADD,
                    1,
                    OP_NUMEQUAL,
                ]
            ), is_taproot=True
        )

    # Test all the combinations for a 2-of-3
    pubkeys = [pk() for _ in range(3)]
    ms = fragments.MultiA(2, [DescriptorKey(k) for k in pubkeys])
    sat_material = SatisfactionMaterial()
    assert ms.satisfy(sat_material) is None
    sat_material.signatures[pubkeys[0]] = bytes(64)
    assert ms.satisfy(sat_material) is None
    sat_material.signatures[pubkeys[1]] = int(1).to_bytes(64, "big")
    assert ms.satisfy(sat_material) == [bytes(64), int(1).to_bytes(64, "big"), b""]
    sat_material.signatures[pubkeys[2]] = int(2).to_bytes(64, "big")
    assert ms.satisfy(sat_material) == [bytes(64), int(1).to_bytes(64, "big"), b""]
    del sat_material.signatures[pubkeys[0]]
    assert ms.satisfy(sat_material) == [
        b"",
        int(1).to_bytes(64, "big"),
        int(2).to_bytes(64, "big"),
    ]
    sat_material.signatures[pubkeys[0]] = bytes(64)
    del sat_material.signatures[pubkeys[1]]
    assert ms.satisfy(sat_material) == [
        bytes(64),
        b"",
        int(2).to_bytes(64, "big"),
    ]
