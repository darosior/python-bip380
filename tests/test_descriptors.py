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
from bip380.descriptors import Descriptor
from bip380.miniscript import SatisfactionMaterial
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
