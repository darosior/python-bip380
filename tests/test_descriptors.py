import coincurve
import os

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
from miniscript.descriptors import Descriptor
from miniscript.miniscript.satisfaction import SatisfactionMaterial
from miniscript.utils.hashes import sha256


def sat_test(
    descriptor,
    keypairs={},
    sat_material=None,
):
    """Test a descriptor's satisfaction against libbitcoinconsensus."""
    # Create a dummy spending transaction
    amount = 10_000
    txid = bytes.fromhex(
        "652c60ec08280356e8c78be9bf4d44276acef3189ba8223e426b757aeabd66ad"
    )
    txin = CMutableTxIn(COutPoint(txid, 0))
    txout = CMutableTxOut(amount - 1_000, descriptor.script_pubkey)
    tx = CMutableTransaction([txin], [txout])

    # Now populate the "signing data". Tell the satisfier about the available timelocks
    # and signatures. Since we'll check them, produce valid sigs for the dummy tx.
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

    # Pretty hacky but hey
    if sat_material is not None:
        sat_material.signatures = signatures
        stack = descriptor.satisfy(sat_material)
    else:
        stack = descriptor.satisfy(list(signatures.values())[0])

    # Finally check it against libbitcoinconsensus. Note this is missing Taproot's flags
    # but we don't care as we only support P2WSH for now.
    ConsensusVerifyScript(
        scriptSig=txin.scriptSig,
        scriptPubKey=CScriptBitcoinTx(iter(descriptor.script_pubkey)),
        txTo=tx,
        inIdx=0,
        amount=amount,
        witness=CScriptWitness(stack),
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
    sat_test(
        desc,
        keypairs={pubkey: privkey},
        sat_material=sat_material,
    )


def test_wpkh_sanity_checks():
    """Sanity check we can parse a wpkh descriptor and satisfy it."""
    hd = BIP32.from_seed(os.urandom(32))
    pubkey, privkey = hd.get_pubkey_from_path("m"), hd.get_privkey_from_path("m")
    desc_str = f"wpkh({pubkey.hex()})"
    desc = Descriptor.from_str(desc_str)
    sat_test(desc, keypairs={pubkey: privkey})
