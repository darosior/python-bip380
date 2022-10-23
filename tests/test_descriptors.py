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
from bip380.key import DescriptorKey, KeyPathKind
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


def test_xpub_parsing():
    """Roundtrip xpubs with various metadata."""
    xpubs = [
        "[aabbccdd]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa",
        "[aabbccdd/0/1'/2]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa",
        "xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/1'/2",
        "xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/145/*",
        "[aabbccdd/0/1'/2]xpub661MyMwAqRbcGC7awXn2f36qPMLE2x42cQM5qHrSRg3Q8X7qbDEG1aKS4XAA1PcWTZn7c4Y2WJKCvcivjpZBXTo8fpCRrxtmNKW4H1rpACa/1'/2/*",
    ]
    for xpub in xpubs:
        assert str(DescriptorKey(xpub)) == xpub


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
    print(desc)
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
