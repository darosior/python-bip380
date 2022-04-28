import coincurve
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
from bip380.descriptors import Descriptor
from bip380.miniscript import SatisfactionMaterial
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

    # Deriving an xpub will derive it
    desc_str = (
        "wsh(pkh(xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa))"
    )
    desc, desc2 = Descriptor.from_str(desc_str), Descriptor.from_str(desc_str)
    desc2.derive(1001)
    assert desc2.keys[0].origin.path == [1001]
    assert (
        str(desc2).split("#")[0].split("]")[1]
        == "xpub68Raazrdpq1a2PhmuPMr59H5eT3axiWPVnbN6t6xJj5YvWRTJhdJr2V9ye7v4VG3yKaPb4qbW2zrHsEHCAzMSUskzNvksL4vtG7DGv12Nj6))"
    )
