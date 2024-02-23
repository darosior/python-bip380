import coincurve
import os
import pytest

from bip32 import BIP32, HARDENED_INDEX
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
from bip380.descriptors import Descriptor
from bip380.key import DescriptorKey, KeyPathKind, DescriptorKeyError
from bip380.miniscript import Node, SatisfactionMaterial, fragments
from bip380.descriptors.errors import DescriptorParsingError
from bip380.utils.hashes import sha256


def sign_dummy_tx(
    descriptor,
    keypairs,
):
    """Create and sign a dummy transaction with the given keys."""
    amount = 10_000
    txid = bytes.fromhex(
        "652c60ec08280356e8c78be9bf4d44276acef3189ba8223e426b757aeabd66ad"
    )
    txin = CMutableTxIn(COutPoint(txid, 0))
    txout = CMutableTxOut(amount - 1_000, descriptor.script_pubkey)
    tx = CMutableTransaction([txin], [txout])

    sighash = RawBitcoinSignatureHash(
        script=descriptor.script_sighash,
        txTo=tx,
        inIdx=0,
        hashtype=1,  # SIGHASH_ALL
        amount=amount,
        sigversion=SIGVERSION_WITNESS_V0,
    )[0]
    signatures = {}
    for pubkey, privkey in keypairs.items():
        sig = coincurve.PrivateKey(privkey).sign(sighash, hasher=None)
        signatures[pubkey] = sig + b"\x01"  # SIGHASH_ALL

    return tx, signatures, amount


def verify_tx(descriptor, tx, witness_stack, amount):
    """Test a transaction's first input spending a given descriptor against libbitcoinconsensus."""
    ConsensusVerifyScript(
        scriptSig=tx.vin[0].scriptSig,
        scriptPubKey=CScriptBitcoinTx(iter(descriptor.script_pubkey)),
        txTo=tx,
        inIdx=0,
        amount=amount,
        witness=CScriptWitness(witness_stack),
        # NOTE: that's missing Taproot flags
        flags=BITCOINCONSENSUS_ACCEPTED_FLAGS,
    )


def roundtrip_desc(desc_str):
    desc = Descriptor.from_str(desc_str)
    assert str(desc) == desc_str
    return desc


def test_wsh_sanity_checks():
    """Sanity check we can parse a wsh descriptor and satisfy it."""
    hd = BIP32.from_seed(os.urandom(32))
    pubkey, privkey = hd.get_pubkey_from_path("m"), hd.get_privkey_from_path("m")
    preimage = os.urandom(32)
    digest = sha256(preimage)

    desc_str = f"wsh(and_b(pk({pubkey.hex()}),a:sha256({digest.hex()})))"
    desc = Descriptor.from_str(desc_str)

    sat_material = SatisfactionMaterial(preimages={digest: preimage})
    tx, signatures, amount = sign_dummy_tx(desc, keypairs={pubkey: privkey})
    sat_material.signatures = signatures

    stack = desc.satisfy(sat_material)
    verify_tx(desc, tx, stack, amount)


def test_wpkh_sanity_checks():
    """Sanity check we can parse a wpkh descriptor and satisfy it."""
    hd = BIP32.from_seed(os.urandom(32))
    pubkey, privkey = hd.get_pubkey_from_path("m"), hd.get_privkey_from_path("m")

    desc_str = f"wpkh({pubkey.hex()})"
    desc = Descriptor.from_str(desc_str)

    tx, signatures, amount = sign_dummy_tx(desc, keypairs={pubkey: privkey})
    stack = desc.satisfy(list(signatures.values())[0])
    verify_tx(desc, tx, stack, amount)


def test_key_parsing():
    """Roundtrip keys with various metadata."""
    keys = [
        "[aabbccdd]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa",
        "[aabbccdd/0/1'/2]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa",
        "xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/1'/2",
        "xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/145/*",
        "[aabbccdd/0/1'/2]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/1'/2/*",
        "xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/*'",
        "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/<0;1;42;9854>",
        "[aabbccdd/0/1'/2]tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/<0;1;42;9854>",
        "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/<0;1;9854>/0/5/10",
        "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/<0;1;9854>/3456/9876/*",
        "[abcdef00/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/<0;1>/*",
        "[abcdef00/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/9478'/<0';1'>/8'/*'",
        "02cc24adfed5a481b000192042b2399087437d8eb16095c3dda1d45a4fbf868017",
        "[0011bbdd/534/789'/34]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a",
        "cc24adfed5a481b000192042b2399087437d8eb16095c3dda1d45a4fbf868017",
        "[0011bbdd/534/789'/34]3d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a",
    ]
    for key in keys:
        assert str(DescriptorKey(key)) == key

    tpub = DescriptorKey(
        "[abcdef00/0'/1]tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/9478'/<0';1';420>/8'/*'"
    )
    assert tpub.path.paths == [
        [9478 + HARDENED_INDEX, 0 + HARDENED_INDEX, 8 + HARDENED_INDEX],
        [9478 + HARDENED_INDEX, 1 + HARDENED_INDEX, 8 + HARDENED_INDEX],
        [9478 + HARDENED_INDEX, 420, 8 + HARDENED_INDEX],
    ]
    assert tpub.path.kind == KeyPathKind.WILDCARD_HARDENED
    assert tpub.origin.fingerprint == bytes.fromhex("abcdef00")
    assert tpub.origin.path == [0 + HARDENED_INDEX, 1]

    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/<0;1;42;9854"
        )
    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/0;1;42;9854>"
        )
    with pytest.raises(
        DescriptorKeyError, match="May only have a single multipath step"
    ):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/4/<0;1>/96/<0;1>"
        )
    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/4/<0>"
        )
    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/4/<0;>"
        )
    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/4/<;1>"
        )
    with pytest.raises(DescriptorKeyError, match="Invalid derivation index"):
        DescriptorKey(
            "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2/4/<0;1;>"
        )


def test_descriptor_parsing():
    """Misc descriptor parsing checks."""
    # Without origin
    Descriptor.from_str(
        "wpkh(033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
    )
    Descriptor.from_str(
        "wpkh(xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu)"
    )
    Descriptor.from_str(
        "wsh(pkh(033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a))"
    )
    Descriptor.from_str(
        "wsh(pkh(xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu))"
    )

    # With origin, only fingerprint
    Descriptor.from_str(
        "wpkh([00aabbcc]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
    )
    Descriptor.from_str(
        "wpkh([00aabbcc]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu)"
    )
    Descriptor.from_str(
        "wsh(pkh([00aabbcc]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a))"
    )
    Descriptor.from_str(
        "wsh(pkh([00aabbcc]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu))"
    )

    # With origin, fingerprint + various derivation paths
    desc = Descriptor.from_str(
        "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
    )
    assert desc.keys[0].origin.fingerprint == bytes.fromhex("00aabbcc") and desc.keys[
        0
    ].origin.path == [0]
    desc = Descriptor.from_str(
        "wpkh([00aabbcc/0/1']xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu)"
    )
    assert desc.keys[0].origin.fingerprint == bytes.fromhex("00aabbcc") and desc.keys[
        0
    ].origin.path == [0, 2 ** 31 + 1]
    desc = Descriptor.from_str(
        "wsh(pkh([00aabbcc/0h/1]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a))"
    )
    assert desc.keys[0].origin.fingerprint == bytes.fromhex("00aabbcc") and desc.keys[
        0
    ].origin.path == [2 ** 31, 1]
    desc = Descriptor.from_str(
        "wsh(pkh([00aabbcc/108765H/578h/9897'/23]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu))"
    )
    assert desc.keys[0].origin.fingerprint == bytes.fromhex("00aabbcc") and desc.keys[
        0
    ].origin.path == [2 ** 31 + 108765, 2 ** 31 + 578, 2 ** 31 + 9897, 23]

    # With checksum
    Descriptor.from_str(
        "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)#g6gm8u7v"
    )
    Descriptor.from_str(
        "wpkh([00aabbcc/1]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu)#2h49p59p"
    )
    Descriptor.from_str(
        "wsh(pkh([00aabbcc/2]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a))#nue4wg6d"
    )
    Descriptor.from_str(
        "wsh(pkh([00aabbcc/3]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu))#zv3q322g"
    )

    # With key derivation path
    desc = Descriptor.from_str(
        "wpkh([00aabbcc/1]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu/*)"
    )
    assert desc.keys[0].path.paths == [[]]
    assert desc.keys[0].path.kind == KeyPathKind.WILDCARD_UNHARDENED
    desc = Descriptor.from_str(
        "wpkh([00aabbcc/1]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu/0/2/3242/5H/2'/*h)"
    )
    assert desc.keys[0].path.paths == [[0, 2, 3242, 5 + 2 ** 31, 2 + 2 ** 31]]
    assert desc.keys[0].path.kind == KeyPathKind.WILDCARD_HARDENED

    # Multiple origins
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/0][00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
        )
    # Too long fingerprint
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbccd/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
        )
    # Insane deriv path
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/0//]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
        )
    # Absent checksum while required
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)",
            strict=True,
        )
    # Invalid checksum
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)#2h49p5pp"
        )
    # Invalid key path
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/1]xpub6BsJ4SAX3CYhcZVV9bFVvmGJ7cyboy4LJqbRJJEziPvm9Pq7v7cWkBAa1LixG9vJybxHDuWcHTtq3K4tsaKG1jMJcpZmkiacFuc7LkzUCWu/0/2//1)"
        )
    # Key path for a raw key
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a/0/1)"
        )

    # Deriving a raw key is a no-op
    desc_str = (
        "wpkh(033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
    )
    desc, desc2 = Descriptor.from_str(desc_str), Descriptor.from_str(desc_str)
    desc2.derive(10)
    assert str(desc2) == str(desc)

    # Deriving a raw key is a no-op, even if it has an origin
    desc_str = "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)"
    desc, desc2 = Descriptor.from_str(desc_str), Descriptor.from_str(desc_str)
    desc2.derive(10)
    assert str(desc2) == str(desc)

    # Deriving an xpub will derive it if it is a wildcard
    desc_str = "wsh(pkh(xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/*))"
    desc, desc2 = Descriptor.from_str(desc_str), Descriptor.from_str(desc_str)
    desc2.derive(1001)
    assert desc2.keys[0].origin.path == [1001]
    assert (
        str(desc2).split("#")[0].split("]")[1]
        == "xpub68Raazrdpq1a2PhmuPMr59H5eT3axiWPVnbN6t6xJj5YvWRTJhdJr2V9ye7v4VG3yKaPb4qbW2zrHsEHCAzMSUskzNvksL4vtG7DGv12Nj6))"
    )
    assert desc2.keys[0].bytes() == bytes.fromhex(
        "03c6844a957551c64e780783fc95b1aeeb040d160f84535b4810f932072db12f25"
    )

    # Deriving an xpub will NOT derive it if it was not a wildcard
    desc_str = "wsh(pkh(xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa))"
    desc, desc2 = Descriptor.from_str(desc_str), Descriptor.from_str(desc_str)
    desc2.derive(1001)
    assert str(desc2) == str(desc)

    # Test against a Revault deposit descriptor using rust-miniscript
    xpub = BIP32.from_xpub(
        "tpubD6NzVbkrYhZ4YgUwLbJjHAo4khrBPHJfZ1nzeeWxaTpYHzvM7SaEFLnuWjcRt8aM3LicBzeqVcN4fKsbTzHSkUJn388HSc5Xxpd1tPSmDYQ"
    )
    assert (
        xpub.get_pubkey_from_path([0]).hex()
        == "02cc24adfed5a481b000192042b2399087437d8eb16095c3dda1d45a4fbf868017"
    )
    desc_str = "wsh(multi(5,tpubD6NzVbkrYhZ4YgUwLbJjHAo4khrBPHJfZ1nzeeWxaTpYHzvM7SaEFLnuWjcRt8aM3LicBzeqVcN4fKsbTzHSkUJn388HSc5Xxpd1tPSmDYQ/*,tpubD6NzVbkrYhZ4X9w1pgeFqiDm7o4dkvEku1ibW6frK5n3vWsSGjxoo3DESgwwZW5N8eN72vCywJzmbezhQQHMbpUytZcxYYTAEaQzUntBEtP/*,tpubD6NzVbkrYhZ4X2M619JZbwnPoQ65e5qzosWPtXYMnMtevcQTwVHq6HFbu5whCAp4PpynzrE65MXk2kgqUb22aE2V5NPZJautw8vXDmVMGuz/*,tpubD6NzVbkrYhZ4YNHo23GAaYnfs8xzyhxpaWZsHJ72a9RPwiQd36BtyHnpRSQFYAJMLK2tWb6i7QJcjNuko4b4V3kGyhe6Z4TxZGXJfEvTU12/*,tpubD6NzVbkrYhZ4YdMUbJuBi6mhtYAC53MevdrFtpQicPavbnYDni6YsAD62NUhQxHYYJpAniVk4Ba9Q2GiptSZPz8ugbo3zgecm2aXQRFny4a/*))#339j7vh3"
    rust_bitcoin_desc_str = "wsh(multi(5,[7fba6fe6/0]02cc24adfed5a481b000192042b2399087437d8eb16095c3dda1d45a4fbf868017,[d7724f76/0]039b2b68caf451ba88afe617cb57f2e9840511bedb0ac8ffa2dc2b25d4ea84adf1,[0c39ed43/0]03f7c1d37ff5dfd5a8b5326533810cef71f7f724fd53d2a88f49e3c63edc5f9688,[e69af179/0]0296209843f0f4dd7b1f3a072e72e7b4edd2e3ff416afc862a7a7aa0b9d40d2de6,[e42852b6/0]03427930b60ba45aeb5c7e03fc3b6b7b22637bec5d355c55204678d7dd8a029981))#vatx0fxr"
    desc = Descriptor.from_str(desc_str)
    assert str(desc) == desc_str
    desc.derive(0)
    # In the string representation they would use raw keys. Do the same for asserting.
    for key in desc.keys:
        key.key = coincurve.PublicKey(key.key.pubkey)
    assert str(desc) == str(rust_bitcoin_desc_str)

    # Same, but to check that the Script is actually being derived too...
    desc_str = "wsh(multi(5,tpubD6NzVbkrYhZ4Yb5yyh2qqUnfGzyakvyzYei3qf2roEMuP7DFB47CDhcUW93YjFGGpwXgUbjeFfoapYyXyyUD2cT1tTzdBCMAhsNTmEJxLM2/*,tpubD6NzVbkrYhZ4Wn1byYeaSwqq6aHni5hQmzHmha8WUgQFH7H5mQ4NZXM8dTs52kqsaxFuau7edrm27ZXNbyp6V5vRJxLZ9oxB92F1dVVAnTn/*,tpubD6NzVbkrYhZ4XLQ56KtSZs1ezkUfD2f1QsUPRvVRqmoo1xsJ9DM6Yao4XKqkEDxGHenroWaooEbpjDTzr7W2LB5CYVPn83eacD1swW38W5G/*,tpubD6NzVbkrYhZ4Ys7ii3MvAhZVowvQRPHwT9uctEnxEmnXR7KtBqyEofT6LmvXov5tpMLDcMhNCC3pi4NrLq1vG51rPcsFGtP5MDHq2F9Bj5Z/*,tpubD6NzVbkrYhZ4WmzxsFZByU1tKop9SWd5YHH81b2gbT5ycGAkZfthcwNAcQZmxswzTvpjBaswKgbcEKksbkGW65wbQsA4DEaCq9c7SqUZ9oi/*))#p26mhq70, deriv index 0, desc wsh(multi(5,[838f8104/0]02de76d54f7e28d731f403f5d1fad4da1df208e1d6e00dbe6dfbadd804461c2743,[24e59fd4/0]02f65c2812d2a8d1da479d0cf32d4ca717263bcdadd4b3f11a014b8cc27f73ec44,[cf0b5330/0]024bf97e1bfc4b5c1de90172d50d92fe072da40a8ccd0f89cd5e858b9dc1226623,[cecf756b/0]023bdc599713ea7b982dc3f439aad24f6c6c8b1a4617f339ba976a48d9067a7d67,[04458729/0]0245cca25b3ecea1a82157bc98b9c35caa53d0f65b9ecb5bfdbb80749d22357c45))#h88gukn3"
    desc_a = Descriptor.from_str(desc_str)
    desc_a.derive(0)
    desc_b = Descriptor.from_str(desc_str)
    desc_b.derive(1)
    assert desc_a.script_pubkey != desc_b.script_pubkey
    assert (
        desc_a.script_pubkey.hex()
        == "002076fb586cb821ac94fbe094e012b93d82cc42925bcf543415416f42aa3ba1822c"
    )
    assert (
        desc_a.witness_script.script.hex()
        == "552102de76d54f7e28d731f403f5d1fad4da1df208e1d6e00dbe6dfbadd804461c27432102f65c2812d2a8d1da479d0cf32d4ca717263bcdadd4b3f11a014b8cc27f73ec4421024bf97e1bfc4b5c1de90172d50d92fe072da40a8ccd0f89cd5e858b9dc122662321023bdc599713ea7b982dc3f439aad24f6c6c8b1a4617f339ba976a48d9067a7d67210245cca25b3ecea1a82157bc98b9c35caa53d0f65b9ecb5bfdbb80749d22357c4555ae"
    )

    # An Unvault descriptor from Revault
    desc_str = "wsh(andor(thresh(1,pk(tpubD6NzVbkrYhZ4Wu1wWF6gEL8tAZvATeGodn1ymPeC3eo9XGdj6fats9QdMG88KZ23FjV4SyTn5LAHLLwRmor4n6yWBH5ccJLnj7LWcuyPuDQ/*)),and_v(v:multi(2,0227cb9432f93edc3ba82ca70c75bda335553a999e6ab885bc337fcb837aa18f4a,02ed00f0a17f220c7b2179ab9610ea2cccaf290c0f726ce472ab959b2528d2b9de),older(9990)),thresh(2,pkh(tpubD6NzVbkrYhZ4Y1KSo5w1yFPreF7THiygs775SRLyMKJZ8ACgtkLJPNb9UiDk4L4MJuYPsdViWfY65tteiub51YZtqjjv6kLKdKH5WSdH7Br/*),a:pkh(tpubD6NzVbkrYhZ4Xhspiqm3eot2TddA2XmcPmqHyRftxFaKkZWuePH4RXw3Af6CpPfnhRBKPjz7TveUGi91EXTph5V7qHYJ4ijG3NtCjrCKPRH/*))))#se46h9uw"
    Descriptor.from_str(desc_str)

    # We can parse a multipath descriptors, and make it into separate single-path descriptors.
    multipath_desc = Descriptor.from_str(
        "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<7';8h;20>/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/<0;1;987>/*)))"
    )
    assert multipath_desc.is_multipath()
    single_path_descs = multipath_desc.singlepath_descriptors()
    assert [str(d) for d in single_path_descs] == [
        str(
            Descriptor.from_str(
                "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/7'/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/0/*)))"
            )
        ),
        str(
            Descriptor.from_str(
                "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/8h/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/1/*)))"
            )
        ),
        str(
            Descriptor.from_str(
                "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/20/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/987/*)))"
            )
        ),
    ]

    # Minisafe descriptor
    Descriptor.from_str(
        "wsh(or_d(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/<0;1>/*),and_v(v:pkh(tpubD9vQiBdDxYzU4cVFtApWj4devZrvcfWaPXX1zHdDc7GPfUsDKqGnbhraccfm7BAXgRgUbVQUV2v2o4NitjGEk7hpbuP85kvBrD4ahFDtNBJ/<0;1>/*),older(65000))))"
    )

    # Even if only one of the keys is multipath
    multipath_desc = Descriptor.from_str(
        "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<0;1>/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/*)))"
    )
    assert multipath_desc.is_multipath()
    single_path_descs = multipath_desc.singlepath_descriptors()
    assert [str(d) for d in single_path_descs] == [
        str(
            Descriptor.from_str(
                "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/0/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/*)))"
            )
        ),
        str(
            Descriptor.from_str(
                "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/1/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/*)))"
            )
        ),
    ]

    # We can detect regular singlepath descs
    desc = Descriptor.from_str(
        "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/4567/*)))"
    )
    assert not desc.is_multipath()

    # We refuse to parse descriptor with multipath key expressions of varying length
    with pytest.raises(
        DescriptorParsingError,
        match="Descriptor contains multipath key expressions with varying length",
    ):
        Descriptor.from_str(
            "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<0;1>/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/<0;1;2;3;4>/*)))"
        )
    with pytest.raises(
        DescriptorParsingError,
        match="Descriptor contains multipath key expressions with varying length",
    ):
        Descriptor.from_str(
            "wsh(andor(pk(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<0;1;2;3>/*),older(10000),pk(tpubD8LYfn6njiA2inCoxwM7EuN3cuLVcaHAwLYeups13dpevd3nHLRdK9NdQksWXrhLQVxcUZRpnp5CkJ1FhE61WRAsHxDNAkvGkoQkAeWDYjV/8/<0;1;2>/*)))"
        )


def test_taproot_key_path():
    def sanity_check_spk(desc_str, spk_hex):
        desc = Descriptor.from_str(desc_str)
        assert desc.script_pubkey.hex() == spk_hex

    # Taken from Bitcoin Core unit tests.
    sanity_check_spk(
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11",
    )
    roundtrip_desc(
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)#dh4fyxrd"
    )
    # Taken from rust-miniscript unit tests.
    sanity_check_spk(
        "tr(02e20e746af365e86647826397ba1c0e0d5cb685752976fe2f326ab76bdc4d6ee9)",
        "51209c19294f03757da3dc235a5960631e3c55751632f5889b06b7a053bdc0bcfbcb",
    )
    roundtrip_desc(
        "tr(02e20e746af365e86647826397ba1c0e0d5cb685752976fe2f326ab76bdc4d6ee9)#f7yg99rk"
    )

    # Works for derived keys too. Taken and adapted from rust-miniscript unit tests.
    desc = Descriptor.from_str(
        "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)"
    )
    desc.derive(0)
    assert (
        str(desc)
        == "tr([a7bea80d/0]xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B)#dx6zghxv"
    )
    for key in desc.keys:
        key.key = coincurve.PublicKeyXOnly(key.key.pubkey[1:])
    assert (
        str(desc)
        == "tr([a7bea80d/0]cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)#26vl7d0e"
    )


def test_taproot_script_path():
    # Badly-formatted tree expressions
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,)"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{)"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,})"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{})"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{,})"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{0,})"
        )
    with pytest.raises(DescriptorParsingError):
        Descriptor.from_str(
            "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{,1})"
        )

    # Parsing of various format of internal keys when there is also a tree expression
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{0,1})#pxx8z3sd"
    )
    assert str(desc.tree.left_child) == str(Node.from_str("0"))
    roundtrip_desc(
        "tr(02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{0,1})#chhcv82t"
    )
    roundtrip_desc(
        "tr([a7bea80d/0]cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{0,1})#kuyl0wph"
    )
    roundtrip_desc(
        "tr([a7bea80d/0]02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{0,1})#582tu5pl"
    )
    roundtrip_desc(
        "tr(tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<0;1>/*,{0,1})#ph24rkjw"
    )
    roundtrip_desc(
        "tr([a7bea80d/9875763'/0]tpubDEN9WSToTyy9ZQfaYqSKfmVqmq1VVLNtYfj3Vkqh67et57eJ5sTKZQBkHqSwPUsoSskJeaYnPttHe2VrkCsKA27kUaN9SDc5zhqeLzKa1rr/0'/<0;1>/*,{0,1})#rc52p8hy"
    )

    # Verify the computation of the merkle root. Checked against Bitcoin Core and rust-miniscript.
    # Single leaf
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,pk(1af85df7c89b9d7b8d7ed881c508df243895c37c2a4ef1a945374d468944da57))#dx2xu7f8"
    )
    assert (
        desc.output_key().format().hex()
        == "49d60cd8db4481ba726e89d9925097949a313e009a6cd81549dcad410f5c69c2"
    )
    # Depth 1, balanced.
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{pk(30925c62aa5db756f2441f18372a22f99e84f3e1db754e4e8d1cf7ff9227556d),pk(1af85df7c89b9d7b8d7ed881c508df243895c37c2a4ef1a945374d468944da57)})#4cly7ykp"
    )
    assert (
        desc.output_key().format().hex()
        == "364033633d10c0bb6af6515778b7245d615546197bfae4f9bceeda4cd55c06f9"
    )
    # Depth 2, imbalanced.
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{pk(30925c62aa5db756f2441f18372a22f99e84f3e1db754e4e8d1cf7ff9227556d),{pk(1af85df7c89b9d7b8d7ed881c508df243895c37c2a4ef1a945374d468944da57),pk(af7453eeac1fc57201cd7813c722c06e12929d7be23c1c025d3afacf2e0b0cfa)}})#ycrkgmjm"
    )
    assert (
        desc.output_key().format().hex()
        == "3baf6fbd5fd8f853feb0bc06b43babcc11aa4583aa423f48047f1ada780a0a6b"
    )
    # Depth 2, imbalanced the other side.
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{{pk(30925c62aa5db756f2441f18372a22f99e84f3e1db754e4e8d1cf7ff9227556d),pk(1af85df7c89b9d7b8d7ed881c508df243895c37c2a4ef1a945374d468944da57)},pk(af7453eeac1fc57201cd7813c722c06e12929d7be23c1c025d3afacf2e0b0cfa)})#xtk7tcz0"
    )
    assert (
        desc.output_key().format().hex()
        == "50858e1c2167b6860b8b1d602a7926e95f77e4e5741c8cb057f767cba69edc29"
    )
    # Depth 2, balanced.
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{{pk(30925c62aa5db756f2441f18372a22f99e84f3e1db754e4e8d1cf7ff9227556d),pk(1af85df7c89b9d7b8d7ed881c508df243895c37c2a4ef1a945374d468944da57)},{pk(af7453eeac1fc57201cd7813c722c06e12929d7be23c1c025d3afacf2e0b0cfa),pk(6cb7bbba9f9f455ddb3e5bd9ac2156dda063706105fe55c5eb0a8457fed32915)}})#e59qvuzs"
    )
    assert (
        desc.output_key().format().hex()
        == "00ca439c5b5eadfdb4c85353a5b76850d28c9ce410cf59f8b04afbc77a2ede6b"
    )

    # A CMS made verify, and back Wdu, for the purpose of exercising various
    # fragments.
    # NOTE: this should be invalid under Taproot context, but at the moment we don't differentiate
    # in the Miniscript logic.
    multi_frag = fragments.Multi(
        2,
        [
            DescriptorKey(
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
            ),
            DescriptorKey(
                "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
            ),
        ],
    )
    convoluted_cms = fragments.WrapA(
        fragments.AndB(
            fragments.WrapU(fragments.WrapT(fragments.WrapV(multi_frag))),
            fragments.WrapA(fragments.WrapL(fragments.Just1())),
        ),
    )
    pk_frag = fragments.WrapC(
        fragments.Pk(
            DescriptorKey(
                "02cc24adfed5a481b000192042b2399087437d8eb16095c3dda1d45a4fbf868017"
            )
        )
    )
    pkh_frag = fragments.WrapC(
        fragments.Pkh(
            DescriptorKey(
                "033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a"
            )
        )
    )
    thresh_frag = fragments.Thresh(
        1, [pkh_frag, fragments.WrapS(pk_frag), convoluted_cms]
    )

    # Single-script tree expressions
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,0)#jfxxeqdf"
    )
    assert str(desc.tree) == str(Node.from_str("0"))
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,1)#ggpdnrdk"
    )
    assert str(desc.tree) == str(Node.from_str("1"))
    with pytest.raises(DescriptorParsingError, match="only available for P2WSH"):
        desc = roundtrip_desc(
            f"tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{thresh_frag})#ar0xk7qv"
        )

    # Deep tree (NOTE: it's ok to repeat keys across leaves)
    desc = roundtrip_desc(
        "tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,\
                {\
                    {\
                        {\
                            pk(6e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea286),\
                            pkh(6e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea286)\
                        },\
                        {\
                            pkh(022f4401b9fbf2f8b3d491cfa307eb6d895b2a5632276461450fb4dc0045f22329),\
                            pk(022f4401b9fbf2f8b3d491cfa307eb6d895b2a5632276461450fb4dc0045f22329)\
                        }\
                    },\
                    {\
                        {\
                            pkh(368045d7d65e1d57c47a5c40ff8b8f382c2d3ef0f1eaf199c1ffac15bb381b95),\
                            pkh(03e1f7ab99d16384daa9ccee2c39ac5de3ff73df288fd8b8752962c8aa975cd8ae)\
                        },\
                        {\
                            pk(026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea286),\
                            pk(026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea286)\
                        }\
                    }\
                }\
            )#0zdzegs3".replace(
            " ", ""
        )
    )

    # TODO: re-enable those once with multi_a instead.
    # Imbalanced trees
    # desc = roundtrip_desc(
        # f"tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{{{{{pk_frag},{pkh_frag}}},{convoluted_cms}}})#7zytn07r"
    # )
    # assert str(desc.tree.left_child.left_child) == str(pk_frag)
    # assert str(desc.tree.left_child.right_child) == str(pkh_frag)
    # assert str(desc.tree.right_child) == str(convoluted_cms)
    # desc = roundtrip_desc(
        # f"tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{{{pk_frag},{{{pkh_frag},{convoluted_cms}}}}})#6xae907j"
    # )
    # assert str(desc.tree.left_child) == str(pk_frag)
    # assert str(desc.tree.right_child.left_child) == str(pkh_frag)
    # assert str(desc.tree.right_child.right_child) == str(convoluted_cms)


def test_taproot_satisfaction():
    """Cross check the satisfaction against"""

    desc = Descriptor.from_str(
        "tr(e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922,{{{pk(6f3083e8d6e468fc5db3ec3301a259d73110b22310e0640c3b106fda8a5773cc),pkh(4228e97dbded4aab222af59b862cd36bc6756f21f55eadbbee8fb2a6c41a4561)},{pk(f2c463aeda45b31314a5fa8a98970647df2517f2b9786255d5c66dd3520e6b30),pk(fff4b58834e5ff31b2d9c30ec18b9e92de9c299484ce2a4e7ac6d8e3c0062571)}},{{pk(45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78),pk(541522cc80f357d28aa9d3883aacaa312310f915a3237ba52b8107ea33a6bbc6)},{pkh(b0e7f16f04d8fab675658197058f116eca2c3c1b162b8aafb90e066615c51f99),pkh(3ae686f1a11c6d54e99f450e52148a9c38209e9010165c125b0558490e0d766a)}}})#qhxcthy5"
    )
    assert (
        desc.tree.merkle_root().hex()
        == "f24b40c4a4790c55b26d306e64178047d3fb8322e8d0aefe0823be80b9c0a86b"
    )
    dummy_sig = bytes(64)
    desc_keys = set(k.bytes().hex() for k in desc.keys)

    # First test the key path
    material = SatisfactionMaterial(signatures={desc.output_key().format(): dummy_sig})
    assert [e.hex() for e in desc.satisfy(material)] == [
        dummy_sig.hex(),
    ]

    # Then the script path for all the keys
    key_cb = [
        (
            "45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922482065cba2919aa9ca1c62f3943b3a091d82d154a89e15bcddc23f78ad9e62cd2a86719442ce543b69b84c6ccdb58eaab3f0a8803e1d48865a20067dac61d1d4795c638fed8e10481e4874ed3c676a8a51a42875bc1ba435c08fc92ab5027c56",
        ),
        (
            "541522cc80f357d28aa9d3883aacaa312310f915a3237ba52b8107ea33a6bbc6",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f0292243974653ab9357fb76569ac62e8e4bef31a0be7678dbec93585591850a95d9b92a86719442ce543b69b84c6ccdb58eaab3f0a8803e1d48865a20067dac61d1d4795c638fed8e10481e4874ed3c676a8a51a42875bc1ba435c08fc92ab5027c56",
        ),
        (
            "6f3083e8d6e468fc5db3ec3301a259d73110b22310e0640c3b106fda8a5773cc",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922da83bb9bdf7a5a3b0d45a5f811d90fb88495cc4c984ab1b60618a4012833e42782bbc5be7826c9493cfd897c3deea90f0a380b7610657bcdc66b3e0662048fe8a90d03ef4486e773622d8779920cc966db3b0ccbe439c2b86b5f7bb69c9d4ef8",
        ),
        (
            "f2c463aeda45b31314a5fa8a98970647df2517f2b9786255d5c66dd3520e6b30",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f029223513f769ff3e4ec0279cc10f43f1146b5d6bfed72291133ef69ef7357cff5adcc759e7319868d906769d5c29080f5bb195bc75c3f9a22436b6b1f903cb75ebc1a90d03ef4486e773622d8779920cc966db3b0ccbe439c2b86b5f7bb69c9d4ef8",
        ),
        (
            "fff4b58834e5ff31b2d9c30ec18b9e92de9c299484ce2a4e7ac6d8e3c0062571",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f029220e456c80b89ca89d82b09b15464d4f9d157330ea8494193b623b9ce147939c8cc759e7319868d906769d5c29080f5bb195bc75c3f9a22436b6b1f903cb75ebc1a90d03ef4486e773622d8779920cc966db3b0ccbe439c2b86b5f7bb69c9d4ef8",
        ),
    ]
    for key, control_block in key_cb:
        assert key in desc_keys
        material = SatisfactionMaterial(signatures={bytes.fromhex(key): dummy_sig})
        assert [e.hex() for e in desc.satisfy(material)] == [
            dummy_sig.hex(),
            "20" + key + "ac",  # PUSHDATA for 64 bytes, the key, then OP_CHECKSIG
            control_block,
        ]

    # Then the script path for all the key hashes
    key_h_cb = [
        (
            "4228e97dbded4aab222af59b862cd36bc6756f21f55eadbbee8fb2a6c41a4561",
            "74e908762a50669f5f170ecac952023ce4a68a43",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922ee0d7007dce3440c2a083167d8ef0536c3c622699f058f6720e9666fa85430dd82bbc5be7826c9493cfd897c3deea90f0a380b7610657bcdc66b3e0662048fe8a90d03ef4486e773622d8779920cc966db3b0ccbe439c2b86b5f7bb69c9d4ef8",
        ),
        (
            "b0e7f16f04d8fab675658197058f116eca2c3c1b162b8aafb90e066615c51f99",
            "9e6533b1086900a89b734d939d325781e463e086",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f0292254ae6600770c341bbacfb8190fae055e91bb4c131651282265755fe7e85f5bba2bfedf828a6e2335ea2e2ef2874fe7509086ad19418103ad2e3fb664376cb483795c638fed8e10481e4874ed3c676a8a51a42875bc1ba435c08fc92ab5027c56",
        ),
        (
            "3ae686f1a11c6d54e99f450e52148a9c38209e9010165c125b0558490e0d766a",
            "8ee89b2f14917b680653e09272164887e6f43fe2",
            "c1e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922017fb95999131b293ac837fe77ec3b17eb9d57e9c901e40f13d77adbd90bfe422bfedf828a6e2335ea2e2ef2874fe7509086ad19418103ad2e3fb664376cb483795c638fed8e10481e4874ed3c676a8a51a42875bc1ba435c08fc92ab5027c56",
        ),
    ]
    for key, h, control_block in key_h_cb:
        assert key in desc_keys
        material = SatisfactionMaterial(signatures={bytes.fromhex(key): dummy_sig})
        assert [e.hex() for e in desc.satisfy(material)] == [
            dummy_sig.hex(),
            key,  # Key push for the hash preimage
            "76a914"
            + h
            + "88ac",  # DUP HASH160 PUSHDATA for 20 bytes, the hash, EQUALVERIFY, CHECKSIG
            control_block,
        ]

    # If there is a signature for any script path but also for the key path, the satisfier
    # will chose the key path.
    material = SatisfactionMaterial(
        signatures={
            desc.output_key().format(): dummy_sig,
            bytes.fromhex(
                "45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78"
            ): dummy_sig,
        }
    )
    assert [e.hex() for e in desc.satisfy(material)] == [
        dummy_sig.hex(),
    ]

    # If there is a signature for any script path but also for the key path, the satisfier
    # will chose the key path.
    material = SatisfactionMaterial(
        signatures={
            desc.output_key().format(): dummy_sig,
            bytes.fromhex(
                "45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78"
            ): dummy_sig,
        }
    )
    assert [e.hex() for e in desc.satisfy(material)] == [
        dummy_sig.hex(),
    ]

    # Between two leaves at the same depth the satisfier will chose the less expensive leaf
    # to satisfy.
    material = SatisfactionMaterial(
        signatures={
            # For pkh()
            bytes.fromhex(
                "4228e97dbded4aab222af59b862cd36bc6756f21f55eadbbee8fb2a6c41a4561"
            ): dummy_sig,
            # For pk()
            bytes.fromhex(
                "45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78"
            ): dummy_sig,
        }
    )
    sat = desc.satisfy(material)
    assert sat[0] == dummy_sig and sat[1] == bytes.fromhex(
        "2045455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78ac"
    )

    # Between two satisfactions of the same size but at different depths the satifier will
    # choose the less deep one as it makes the merkle proof shorter.
    desc = Descriptor.from_str(
        "tr(e6b631547001c2ca7c6cfb0637df5dcf23540567b7130b42a5560b9fa9f02922,{{pk(6f3083e8d6e468fc5db3ec3301a259d73110b22310e0640c3b106fda8a5773cc),{pk(f2c463aeda45b31314a5fa8a98970647df2517f2b9786255d5c66dd3520e6b30),pk(fff4b58834e5ff31b2d9c30ec18b9e92de9c299484ce2a4e7ac6d8e3c0062571)}},{{pk(45455d3f915ac438c9405467bcf0fcf59d9cf4b25069fb7cef1ace3451c69e78),pk(541522cc80f357d28aa9d3883aacaa312310f915a3237ba52b8107ea33a6bbc6)},{pkh(b0e7f16f04d8fab675658197058f116eca2c3c1b162b8aafb90e066615c51f99),pkh(3ae686f1a11c6d54e99f450e52148a9c38209e9010165c125b0558490e0d766a)}}})"
    )
    material = SatisfactionMaterial(
        signatures={
            # pk() at depth 2
            bytes.fromhex(
                "6f3083e8d6e468fc5db3ec3301a259d73110b22310e0640c3b106fda8a5773cc"
            ): dummy_sig,
            # pk() at depth 3
            bytes.fromhex(
                "f2c463aeda45b31314a5fa8a98970647df2517f2b9786255d5c66dd3520e6b30"
            ): dummy_sig,
        }
    )
    sat = desc.satisfy(material)
    assert sat[0] == dummy_sig and sat[1] == bytes.fromhex(
        "206f3083e8d6e468fc5db3ec3301a259d73110b22310e0640c3b106fda8a5773ccac"
    )
