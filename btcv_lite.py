"""
btcv.py — Bitcoin engine for BTCVault (single-sig: Legacy BIP-44, Nested SegWit BIP-49,
Native SegWit BIP-84, Taproot BIP-86 — PSBT / BIP-174).

LITE / OFFLINE-ONLY engine (no network code, no PSBT builder). Used by btcvault_lite.py. Flow:

    OFFLINE : create wallet  -> encrypted keystore (seed) + watch-only export (xpub)
    ONLINE  : import xpub -> scan balance/UTXOs -> build UNSIGNED PSBT
    OFFLINE : review PSBT -> sign with keystore -> SIGNED PSBT / raw tx
    ONLINE  : broadcast

Interoperable formats (so BlueWallet / Sparrow / Electrum / Keystone-style apps can be on the other side):
    * PSBT as base64 text, binary .psbt file, or BC-UR animated QR (ur:crypto-psbt)  [UR needs cbor2 + ur.py]
    * watch-only key as SLIP-132 zpub/ypub (vpub/upub on test nets) or plain xpub/tpub, key-origin
      "[fp/84h/0h/0h]zpub...", or an output descriptor (wpkh / sh(wpkh) / pkh / tr)

Requires:  pip install embit pycryptodome          (cbor2 optional, for UR QR)

Safety design (the signer does NOT trust the online machine):
    * every input must carry the FULL previous transaction, whose txid is re-hashed and checked, so the
      amounts (and therefore the fee) are proven — this closes the classic SegWit "fee attack".
      (witness_utxo-only PSBTs are refused unless you explicitly allow it.)
    * "change" is decided by re-deriving our own addresses and matching scriptPubKeys; PSBT metadata
      (derivation hints, fingerprints) is only ever used as a hint and is always verified.
    * only SIGHASH_ALL is signed; anything else is refused.
    * the keystore is bound to a network (mainnet / testnet4 / testnet3 / signet / regtest) AND to an
      address type, so coins can't be mixed up.
    * Taproot: key-path spends only (no script trees), SIGHASH_DEFAULT/ALL, BIP-340 signatures that are
      re-verified before anything is exported.

EDUCATIONAL TOOL. Unaudited. Test on signet/testnet with tiny amounts first.
"""

import base64
import hashlib
import json
import os
import re
import time
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_CEILING

from embit import bip32, bip39, ec
from embit import networks as _enet
from embit import script as _escript
from embit.descriptor.checksum import add_checksum
from embit.psbt import PSBT, DerivationPath, PSBTError
from embit.script import Script, Witness
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

# ------------------------------- AES-256-GCM backend -------------------------------
try:                                                   # pycryptodome
    from Crypto.Cipher import AES as _AES

    def _gcm_encrypt(key, nonce, plaintext, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(plaintext)
        return ct + tag

    def _gcm_decrypt(key, nonce, blob, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        return c.decrypt_and_verify(blob[:-16], blob[-16:])       # ValueError if wrong key / tampered
except ImportError:                                    # fallback: 'cryptography'
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

        def _gcm_encrypt(key, nonce, plaintext, aad):
            return _AESGCM(key).encrypt(nonce, plaintext, aad)

        def _gcm_decrypt(key, nonce, blob, aad):
            try:
                return _AESGCM(key).decrypt(nonce, blob, aad)
            except Exception:
                raise ValueError("MAC check failed")
    except ImportError:
        raise ImportError("btcv needs an AES-GCM library:  pip install pycryptodome")

# ---------------------------------- constants --------------------------------------
SAT = 10**8
HARD = 0x80000000
RBF_SEQUENCE = 0xFFFFFFFD
MAX_SCAN = 100                   # addresses per chain checked when matching scripts to our wallet
KS_VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1

NETWORKS = {
    "Bitcoin Mainnet":  {"embit": "main",    "coin": 0, "test": False},
    "Bitcoin Testnet4": {"embit": "test",    "coin": 0, "test": True},
    "Bitcoin Testnet3": {"embit": "test",    "coin": 0, "test": True},
    "Bitcoin Signet":   {"embit": "signet",  "coin": 0, "test": True},
    "Bitcoin Regtest":  {"embit": "regtest", "coin": 1, "test": True},
}
DEFAULT_NET = "Bitcoin Signet"

# SLIP-132 version bytes (testnet4 / testnet3 / signet / regtest all share the "test" set)
_SLIP = {"main": {"xpub": "0488b21e", "ypub": "049d7cb2", "zpub": "04b24746"},
         "test": {"xpub": "043587cf", "ypub": "044a5262", "zpub": "045f1cf6"}}
_SLIP_TO_SCRIPT = {bytes.fromhex(v): {"xpub": None, "ypub": "p2sh-p2wpkh", "zpub": "p2wpkh"}[k]
                   for grp in _SLIP.values() for k, v in grp.items()}
_KNOWN_VERSIONS = set(_SLIP_TO_SCRIPT)

# Address types.  in_vb = virtual size of one input spending it; dust = minimum output value.
SCRIPTS = {
    "p2pkh":       {"label": "Legacy (P2PKH, BIP-44)",             "purpose": 44, "slip": "xpub", "spk": "p2pkh",
                    "in_vb": Decimal("148"),  "spk_len": 25, "dust": 546, "desc": ("pkh(", ")")},
    "p2wpkh":      {"label": "Native SegWit (P2WPKH, BIP-84)",     "purpose": 84, "slip": "zpub", "spk": "p2wpkh",
                    "in_vb": Decimal("68"),   "spk_len": 22, "dust": 294, "desc": ("wpkh(", ")")},
    "p2sh-p2wpkh": {"label": "Nested SegWit (P2SH-P2WPKH, BIP-49)", "purpose": 49, "slip": "ypub", "spk": "p2sh",
                    "in_vb": Decimal("91"),   "spk_len": 23, "dust": 540, "desc": ("sh(wpkh(", "))")},
    "p2tr":        {"label": "Taproot (P2TR, BIP-86)",             "purpose": 86, "slip": "xpub", "spk": "p2tr",
                    "in_vb": Decimal("57.5"), "spk_len": 34, "dust": 330, "desc": ("tr(", ")")},
}
SCRIPT_LABELS = {v["label"]: k for k, v in SCRIPTS.items()}     # GUI label -> id (display order = dict order)
DEFAULT_SCRIPT = "p2wpkh"
_PURPOSE_TO_SCRIPT = {v["purpose"]: k for k, v in SCRIPTS.items()}


def script_label(script: str) -> str:
    return SCRIPTS[script]["label"]


def net_params(name: str) -> dict:
    return _enet.NETWORKS[NETWORKS[name]["embit"]]


# ----------------------------------- helpers ---------------------------------------
def to_btc(sat: int) -> str:
    s = f"{Decimal(int(sat)) / SAT:.8f}".rstrip("0").rstrip(".")
    return s or "0"


def parse_btc(text: str) -> int:
    try:
        d = Decimal(text.strip())
    except (InvalidOperation, AttributeError):
        raise ValueError("Amount is not a number.")
    if d <= 0:
        raise ValueError("Amount must be greater than zero.")
    if d != d.quantize(Decimal("1E-8")):
        raise ValueError("Bitcoin has at most 8 decimal places.")
    return int(d * SAT)


def _ceil(d) -> int:
    return int(Decimal(d).to_integral_value(rounding=ROUND_CEILING))


def vsize_estimate(n_inputs: int, output_spk_lens, script: str = DEFAULT_SCRIPT) -> int:
    """Estimated vsize: per-input cost depends on the address type; output = 8 value + 1 len + script."""
    return _ceil(Decimal("10.5") + SCRIPTS[script]["in_vb"] * n_inputs + sum(9 + n for n in output_spk_lens))


def dust_limit(spk: Script) -> int:
    t = spk.script_type()
    return {"p2wpkh": 294, "p2wsh": 330, "p2tr": 330, "p2sh": 540, "p2pkh": 546}.get(t, 546)


def address_to_spk(addr: str, network: str) -> Script:
    """Parse + validate an address for THIS network (embit alone does not check the network)."""
    a = (addr or "").strip()
    if not a:
        raise ValueError("Address is empty.")
    low = a.lower()
    is_bech32 = low.startswith(("bc1", "tb1", "bcrt1"))
    if is_bech32 and a != low and a != a.upper():
        raise ValueError("Mixed-case bech32 address is invalid.")
    try:
        spk = _escript.address_to_scriptpubkey(a)
        back = spk.address(net_params(network))
    except Exception:
        raise ValueError(f"Not a valid {network} address.")
    if (back.lower() != low) if is_bech32 else (back != a):
        raise ValueError(f"Address is not valid for {network} (wrong network or bad checksum).")
    return spk


def spk_to_address(spk: Script, network: str):
    try:
        return spk.address(net_params(network))
    except Exception:
        return None


def _path_ints(path: str):
    out = []
    for part in path.strip().split("/")[1:]:
        h = part[-1] in "h'H"
        n = int(part[:-1] if h else part)
        out.append(n | HARD if h else n)
    return out


def _norm_path(path: str) -> str:
    return "m/" + "/".join(p.replace("'", "h").replace("H", "h") for p in path.strip().split("/")[1:])


def default_path(network: str, account: int = 0, script: str = DEFAULT_SCRIPT) -> str:
    return f"m/{SCRIPTS[script]['purpose']}h/{NETWORKS[network]['coin']}h/{account}h"


# ------------------------- Taproot (BIP-340 / BIP-341, key-path only) ---------------------
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, _P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, _P)) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _pt_mul(k, pt=_G):
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, pt)
        pt = _pt_add(pt, pt)
        k >>= 1
    return r


def _tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def _lift_x(x: int):
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        raise ValueError("Not a valid x-only public key.")
    return x, (y if y % 2 == 0 else _P - y)


def taproot_output_key(pub_sec: bytes) -> bytes:
    """BIP-86: 32-byte x-only output key = P + H_TapTweak(P)·G  (no script tree)."""
    px = bytes(pub_sec)[1:33]
    t = int.from_bytes(_tagged_hash("TapTweak", px), "big")
    if t >= _N:
        raise ValueError("Invalid taproot tweak.")
    q = _pt_add(_lift_x(int.from_bytes(px, "big")), _pt_mul(t))
    if q is None:
        raise ValueError("Invalid taproot output key.")
    return q[0].to_bytes(32, "big")


def taproot_tweak_secret(secret: bytes) -> int:
    """BIP-86 tweaked private scalar for the internal key `secret` (32 bytes)."""
    d = int.from_bytes(secret, "big")
    pt = _pt_mul(d)
    if pt[1] % 2:
        d = _N - d
    t = int.from_bytes(_tagged_hash("TapTweak", pt[0].to_bytes(32, "big")), "big")
    return (d + t) % _N


def schnorr_sign(d: int, msg: bytes, aux: bytes) -> bytes:
    pt = _pt_mul(d)
    if pt[1] % 2:
        d = _N - d
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k = int.from_bytes(_tagged_hash("BIP0340/nonce", t + px + msg), "big") % _N
    if k == 0:
        raise RuntimeError("Nonce generation failed.")
    r = _pt_mul(k)
    if r[1] % 2:
        k = _N - k
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rx + px + msg), "big") % _N
    return rx + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(xonly: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        pt = _lift_x(int.from_bytes(xonly, "big"))
    except ValueError:
        return False
    if len(sig) != 64:
        return False
    r, sv = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= _P or sv >= _N:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + xonly + msg), "big") % _N
    q = _pt_add(_pt_mul(sv), _pt_mul(_N - e, pt))
    return q is not None and q[1] % 2 == 0 and q[0] == r


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def taproot_sighash(tx: Transaction, values, spks, index: int, hash_type: int = 0) -> bytes:
    """BIP-341 key-path signature hash. `values` / `spks` cover EVERY input of the transaction."""
    if hash_type not in (0, 1):
        raise ValueError("Only SIGHASH_DEFAULT / SIGHASH_ALL are supported for Taproot.")
    sha = lambda b: hashlib.sha256(b).digest()               # noqa: E731
    prevouts = b"".join(bytes.fromhex(i.txid.hex())[::-1] + int(i.vout).to_bytes(4, "little") for i in tx.vin)
    amounts = b"".join(int(v).to_bytes(8, "little") for v in values)
    scripts = b"".join(_varint(len(s)) + bytes(s) for s in spks)
    seqs = b"".join(int(i.sequence).to_bytes(4, "little") for i in tx.vin)
    outs = b"".join(int(o.value).to_bytes(8, "little") + _varint(len(o.script_pubkey.data)) + o.script_pubkey.data
                    for o in tx.vout)
    msg = (bytes([hash_type]) + int(tx.version).to_bytes(4, "little") + int(tx.locktime).to_bytes(4, "little")
           + sha(prevouts) + sha(amounts) + sha(scripts) + sha(seqs) + sha(outs)
           + b"\x00" + int(index).to_bytes(4, "little"))       # spend_type 0: key path, no annex
    return _tagged_hash("TapSighash", b"\x00" + msg)


def _push(data: bytes) -> bytes:
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


# ----------------------------------- keystore --------------------------------------
def _norm_pw(pw: str) -> bytes:
    return unicodedata.normalize("NFKC", pw).encode()


def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not (2**12 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise ValueError("Keystore has unreasonable scrypt parameters; refusing to open it.")
    return hashlib.scrypt(_norm_pw(password), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2**30)


def _aad(meta: dict) -> bytes:
    keep = {k: meta[k] for k in ("btcvault", "network", "script", "path", "fingerprint", "passphrase")}
    return json.dumps(keep, sort_keys=True, separators=(",", ":")).encode()


def normalize_mnemonic(words: str) -> str:
    return " ".join(words.lower().split())


def spk_for(script: str, pub) -> Script:
    """scriptPubKey of a single-sig address type for a compressed public key."""
    if script == "p2wpkh":
        return _escript.p2wpkh(pub)
    if script == "p2pkh":
        return _escript.p2pkh(pub)
    if script == "p2sh-p2wpkh":
        return _escript.p2sh(_escript.p2wpkh(pub))
    if script == "p2tr":
        return Script(b"\x51\x20" + taproot_output_key(pub.sec()))
    raise ValueError("Unknown address type.")


class Watch:
    """Public account data (account-level xpub). Safe to keep on an ONLINE machine."""

    def __init__(self, network: str, key: bip32.HDKey, fingerprint=None, path=None, script: str = DEFAULT_SCRIPT):
        if network not in NETWORKS:
            raise ValueError("Unknown network.")
        if script not in SCRIPTS:
            raise ValueError("Unknown address type.")
        self.network = network
        self.script = script
        self.key = key.to_public() if key.is_private else key
        self.fp = bytes(fingerprint) if fingerprint else b"\x00" * 4
        self.path = _norm_path(path) if path else default_path(network, 0, script)
        self._ck = {}
        self._cache = {}

    @property
    def fp_hex(self) -> str:
        return self.fp.hex()

    def _child(self, chain: int, idx: int):
        if (chain, idx) not in self._cache:
            if chain not in self._ck:
                self._ck[chain] = self.key.derive([chain])
            self._cache[(chain, idx)] = self._ck[chain].derive([idx])
        return self._cache[(chain, idx)]

    def pubkey(self, chain: int, idx: int):
        return self._child(chain, idx).get_public_key()

    def spk(self, chain: int, idx: int) -> Script:
        return spk_for(self.script, self._child(chain, idx).get_public_key())

    def address(self, chain: int, idx: int) -> str:
        return self.spk(chain, idx).address(net_params(self.network))

    def derivation(self, chain: int, idx: int):
        return _path_ints(self.path) + [chain, idx]

    # ---- exports ----
    def _version(self, kind: str) -> bytes:
        return bytes.fromhex(_SLIP["main" if NETWORKS[self.network]["embit"] == "main" else "test"][kind])

    def slip132(self) -> str:
        """zpub/vpub (native), ypub/upub (nested), plain xpub/tpub (legacy, taproot)."""
        return self.key.to_base58(version=self._version(SCRIPTS[self.script]["slip"]))

    def xpub(self) -> str:
        return self.key.to_base58(version=self._version("xpub"))

    def key_origin(self) -> str:
        return f"[{self.fp_hex}{self.path[1:]}]{self.slip132()}"

    def descriptors(self):
        op, cl = SCRIPTS[self.script]["desc"]
        base = f"{op}[{self.fp_hex}{self.path[1:]}]{self.xpub()}"
        return add_checksum(base + "/0/*" + cl), add_checksum(base + "/1/*" + cl)

    def export_text(self) -> str:
        ext, chg = self.descriptors()
        return (f"# BTCVault watch-only export — {self.network} — {script_label(self.script)}\n"
                f"# PUBLIC data only. Safe for an online machine, but it reveals ALL your addresses/balance.\n"
                f"key-origin: {self.key_origin()}\n"
                f"ext. pubkey: {self.slip132()}\n"
                f"receive   : {ext}\n"
                f"change    : {chg}\n"
                f"first address: {self.address(0, 0)}\n")


# ------------------------- Keystone / BC-UR key export (pairing QR) -----------------------
# Software wallets (UniSat, OKX, Sparrow, BlueWallet, Nunchuk …) pair with a Keystone by scanning:
#   ur:crypto-multi-accounts   Keystone's own export (registry type 1103) — what UniSat / OKX ask Keystone for
#   ur:crypto-account          BCR-2020-015 (master fingerprint + script descriptors) — Sparrow, BlueWallet, …
# Byte layout mirrors the real device firmware (Keystone-cold-app: URRegistryHelper / OKXWalletViewModel):
#   every hdkey carries use-info (coin type + network), origin WITH depth, parent fingerprint, name "Keystone".
# Signing needs nothing new: both directions are ur:crypto-psbt (already supported).
# NOTE: OKX / UniSat accept MAINNET only — a test-network export is flagged network=1 and OKX rejects it with
#       "This action is not supported on the current network type".
KS_DEVICE = "Keystone Pro"       # what the device reports (DeviceInfoUtil: "Keystone Pro" / "Keystone Essential")
KS_KEY_NAME = "Keystone"         # hdkey name field (URRegistryHelper.KEY_NAME)
KS_DEVICE_VERSION = None         # the Keystone-cold firmware sends none; set e.g. "2.0.0" only if a wallet asks
_UR_OUTPUT_TAG = {"p2pkh": (403,), "p2wpkh": (404,), "p2sh-p2wpkh": (400, 404), "p2tr": (409,)}   # BCR-2020-010


def _comps(ints):
    out = []
    for n in ints:
        out += [n & ~HARD, bool(n & HARD)]
    return out


def keystone_bundle(wallet) -> dict:
    """Everything a Keystone-style pairing needs, as PUBLIC data only (call once while the keystore is open):
         watches : account-0 Watch for every address type (Legacy, Nested, Native, Taproot)
         eth     : the device's Ethereum keys (BIP-44 standard + 10 Ledger-Live accounts) as crypto-hdkey items.
                   OKX's Keystone import expects them (it supports BTC + EVM from one scan)."""
    import cbor2
    watches = []
    for sc in SCRIPTS:
        path = default_path(wallet.network, 0, sc)
        watches.append(Watch(wallet.network, wallet.root.derive(path).to_public(), wallet.fp, path, sc))
    fp = int.from_bytes(wallet.fp, "big")
    net = 1 if NETWORKS[wallet.network]["test"] else 0
    std = wallet.root.derive("m/44h/60h/0h").to_public()
    eth = [cbor2.CBORTag(303, {
        3: bytes(std.get_public_key().sec()), 4: bytes(std.chain_code),
        5: cbor2.CBORTag(305, {1: 60, 2: net}),
        6: cbor2.CBORTag(304, {1: _comps(_path_ints("m/44h/60h/0h")), 2: fp, 3: 3}),
        7: cbor2.CBORTag(304, {1: [0, False, [], False]}),            # BIP-44 standard: m/44'/60'/0'/0/*
        8: int.from_bytes(std.fingerprint, "big"), 9: KS_KEY_NAME, 10: "account.standard"})]
    for i in range(10):                                                # Ledger Live: m/44'/60'/i'/0/0 (bare public keys)
        p = f"m/44h/60h/{i}h/0/0"
        k = wallet.root.derive(p).to_public()
        eth.append(cbor2.CBORTag(303, {
            3: bytes(k.get_public_key().sec()),
            6: cbor2.CBORTag(304, {1: _comps(_path_ints(p)), 2: fp, 3: 5}),
            9: KS_KEY_NAME, 10: "account.ledger_live"}))
    return {"watches": watches, "eth": eth}


def all_account_watches(wallet) -> list:
    return keystone_bundle(wallet)["watches"]


def _hdkey_cbor(watch: Watch, children: bool = False):
    """crypto-hdkey (tag 303), field-for-field like the device: key, chain code, use-info, origin(+depth),
    parent fingerprint, name."""
    import cbor2
    if watch.fp == b"\x00" * 4:
        raise ValueError("This key has no master fingerprint (bare xpub) — export from the wallet's own keystore "
                         "(tab 2) so the QR carries the fingerprint hardware-wallet flows need.")
    ints = _path_ints(watch.path)
    m = {3: bytes(watch.key.get_public_key().sec()), 4: bytes(watch.key.chain_code),
         5: cbor2.CBORTag(305, {1: 0, 2: 1 if NETWORKS[watch.network]["test"] else 0}),       # BTC, network
         6: cbor2.CBORTag(304, {1: _comps(ints), 2: int.from_bytes(watch.fp, "big"), 3: len(ints)})}
    if children:
        m[7] = cbor2.CBORTag(304, {1: [0, False, [], False]})      # .../0/*   (wildcard = empty component)
    m[8] = int.from_bytes(watch.key.fingerprint, "big")           # parent fingerprint
    m[9] = KS_KEY_NAME
    return cbor2.CBORTag(303, m)


def keystone_multi_accounts(bundle, device: str = None, device_id: str = None) -> tuple:
    """(ur_type, cbor_bytes) for ur:crypto-multi-accounts — what the OKX wallet reads from a Keystone.
    Same content and order as the device (OKXWalletViewModel): ETH keys, then BTC 44' / 49' / 84'.
    `bundle`: keystone_bundle() dict, or a Watch / list of Watch for a BTC-only export."""
    import cbor2
    if isinstance(bundle, dict):
        ws, eth = bundle["watches"], bundle.get("eth", [])
    else:
        ws, eth = ([bundle] if isinstance(bundle, Watch) else list(bundle)), []
    ws = [w for w in ws if w.script != "p2tr"] if len(ws) > 1 else ws     # the device exports 44/49/84 only
    order = {"p2pkh": 0, "p2sh-p2wpkh": 1, "p2wpkh": 2}
    ws = sorted(ws, key=lambda w: order.get(w.script, 9))
    fp = ws[0].fp
    if any(w.fp != fp or w.network != ws[0].network for w in ws):
        raise ValueError("All exported accounts must come from the same seed and network.")
    dev_id = device_id or hashlib.sha256(hashlib.sha256(b"keystone" + b"btcvault" + fp).digest()).hexdigest()[:40]
    body = {1: int.from_bytes(fp, "big"), 2: list(eth) + [_hdkey_cbor(w) for w in ws],
            3: device or KS_DEVICE, 4: dev_id}
    if KS_DEVICE_VERSION:
        body[5] = KS_DEVICE_VERSION
    return "crypto-multi-accounts", cbor2.dumps(body)


def keystone_account(watches) -> tuple:
    """(ur_type, cbor_bytes) for ur:crypto-account (BCR-2020-015). This is what UniSat (and BlueWallet / Sparrow)
    parse: ONE descriptor per address type — UniSat looks up m/44'/0'/0' first, so every type must be present."""
    import cbor2
    if isinstance(watches, dict):
        watches = watches["watches"]
    ws = [watches] if isinstance(watches, Watch) else list(watches)
    fp = ws[0].fp
    if any(w.fp != fp or w.network != ws[0].network for w in ws):
        raise ValueError("All exported accounts must come from the same seed and network.")
    outs = []
    for w in ws:
        node = _hdkey_cbor(w, children=True)
        for tag in reversed(_UR_OUTPUT_TAG[w.script]):
            node = cbor2.CBORTag(tag, node)
        outs.append(node)
    return "crypto-account", cbor2.dumps({1: int.from_bytes(fp, "big"), 2: outs})


def keystone_frames(bundle, kind: str = "multi", max_fragment: int = 160):
    """Animated-QR strings. kind: 'multi' (OKX) or 'account' (UniSat, BlueWallet, Sparrow)."""
    import ur
    typ, body = keystone_multi_accounts(bundle) if kind == "multi" else keystone_account(bundle)
    return ur.ur_encode_frames(typ, body, max_fragment)


_ORIGIN = re.compile(r"\[([0-9a-fA-F]{8})((?:/\d+[hH'])*)\]")
_XKEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([xztvyu]pub[1-9A-HJ-NP-Za-km-z]{100,112})(?![1-9A-HJ-NP-Za-km-z])")
_BADKEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([YUZV]pub|[xztvyuXYZTUV]prv)[1-9A-HJ-NP-Za-km-z]{100,112}")
_MAIN_VERSIONS = {bytes.fromhex(v) for v in _SLIP["main"].values()}       # xpub, ypub, zpub


def _descriptor_script(text: str):
    low = text.lower()
    if "sh(wpkh(" in low:
        return "p2sh-p2wpkh"
    if "wpkh(" in low:
        return "p2wpkh"
    if re.search(r"(?<![a-z])pkh\(", low):
        return "p2pkh"
    if re.search(r"(?<![a-z])tr\(", low):
        return "p2tr"
    return None


def parse_watch(text: str, network: str, script: str = None) -> Watch:
    """Accepts: zpub/ypub/xpub (vpub/upub/tpub on test nets), '[fp/84h/0h/0h]zpub…', or a descriptor
    (wpkh / sh(wpkh) / pkh / tr).  The address type is DETECTED from the key version, the origin path
    or the descriptor; `script` is only used when the text is a bare xpub/tpub with nothing to go on."""
    t = (text or "").strip()
    for line in t.splitlines():                           # allow our own export file (comments + labels)
        s = line.strip()
        if s.startswith("key-origin:"):
            t = s.split(":", 1)[1].strip()
            break
    if re.search(r"[xztvyuXYZTUV]prv", t):
        raise ValueError("That looks like a PRIVATE key. Never paste private keys into the online machine.")
    if _BADKEY.search(t) and not _XKEY.search(t):
        raise ValueError("Only single-sig keys are supported (xpub / ypub / zpub, or tpub / upub / vpub).")
    m = _XKEY.search(t)
    if not m:
        raise ValueError("No extended public key (xpub/ypub/zpub/tpub/upub/vpub) found in the text.")
    try:
        key = bip32.HDKey.from_base58(m.group(1))
    except Exception:
        raise ValueError("The extended public key is malformed (bad checksum?).")
    if key.is_private:
        raise ValueError("Refusing a private key.")
    ver = bytes(key.version)
    if ver not in _KNOWN_VERSIONS:
        raise ValueError("Unrecognised extended-key version.")
    is_main_key = ver in _MAIN_VERSIONS
    if is_main_key == NETWORKS[network]["test"]:
        raise ValueError(f"This key belongs to {'mainnet' if is_main_key else 'a test network'}, "
                         f"but you selected {network}.")
    if key.depth != 3:
        raise ValueError("Expected an ACCOUNT-level key (m/purpose'/coin'/account', depth 3).")
    fp, path, from_path = None, None, None
    o = _ORIGIN.search(t)
    if o:
        fp = bytes.fromhex(o.group(1))
        path = "m" + o.group(2)
        ints = _path_ints(path)
        if len(ints) != 3 or not (ints[0] & HARD) or (ints[0] & ~HARD) not in _PURPOSE_TO_SCRIPT:
            raise ValueError("Only BIP-44/49/84/86 account paths (m/purpose'/coin'/account') are supported.")
        from_path = _PURPOSE_TO_SCRIPT[ints[0] & ~HARD]
        if ints[1] != (NETWORKS[network]["coin"] | HARD):
            raise ValueError("The key's coin-type does not match the selected network.")
    hints = {"key version": _SLIP_TO_SCRIPT[ver], "origin path": from_path, "descriptor": _descriptor_script(t)}
    found = {k: v for k, v in hints.items() if v}
    if len(set(found.values())) > 1:
        raise ValueError("The key contradicts itself about its address type: "
                         + ", ".join(f"{k} says {script_label(v)}" for k, v in found.items()))
    detected = next(iter(found.values()), None)
    chosen = detected or script or DEFAULT_SCRIPT
    if chosen not in SCRIPTS:
        raise ValueError("Unknown address type.")
    w = Watch(network, key, fp, path, chosen)
    w.detected = detected is not None                  # False -> bare xpub: type came from the caller's choice
    return w


class Wallet:
    """Signing-capable wallet. OFFLINE machine only."""

    def __init__(self, mnemonic: str, passphrase: str, network: str, account: int = 0, script: str = DEFAULT_SCRIPT):
        if script not in SCRIPTS:
            raise ValueError("Unknown address type.")
        mnemonic = normalize_mnemonic(mnemonic)
        if not bip39.mnemonic_is_valid(mnemonic):
            raise ValueError("Invalid seed phrase (unknown word or bad checksum).")
        seed = bip39.mnemonic_to_seed(mnemonic, unicodedata.normalize("NFKD", passphrase or ""))
        self.network = network
        self.script = script
        self.root = bip32.HDKey.from_seed(seed, version=net_params(network)["xprv"])
        self.path = default_path(network, account, script)
        self.acct = self.root.derive(self.path)
        self.fp = self.root.my_fingerprint
        self.watch = Watch(network, self.acct.to_public(), self.fp, self.path, script)

    def priv(self, chain: int, idx: int):
        return self.acct.derive([chain, idx])


def new_mnemonic(words: int = 24) -> str:
    return bip39.mnemonic_from_bytes(os.urandom({12: 16, 15: 20, 18: 24, 21: 28, 24: 32}[words]))


def keystore_create(mnemonic: str, password: str, network: str, passphrase: str = "",
                    script: str = DEFAULT_SCRIPT) -> dict:
    mnemonic = normalize_mnemonic(mnemonic)
    w = Wallet(mnemonic, passphrase, network, script=script)
    meta = {"btcvault": KS_VERSION, "network": network, "script": script, "path": w.path,
            "fingerprint": w.fp.hex(), "passphrase": bool(passphrase)}
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _kdf(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    blob = _gcm_encrypt(key, nonce, mnemonic.encode(), _aad(meta))
    ks = dict(meta)
    ks.update({"first_address": w.watch.address(0, 0),
               "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex()},
               "cipher": {"name": "aes-256-gcm", "nonce": nonce.hex()},
               "ciphertext": blob.hex()})
    return ks


def keystore_info(ks: dict) -> dict:
    if ks.get("btcvault") != KS_VERSION or ks.get("network") not in NETWORKS or ks.get("script") not in SCRIPTS:
        raise ValueError("Not a BTCVault Bitcoin keystore.")
    return {k: ks.get(k) for k in ("network", "script", "path", "fingerprint", "passphrase", "first_address")}


def keystore_open(ks: dict, password: str, passphrase: str = "") -> Wallet:
    keystore_info(ks)
    if ks["kdf"].get("name") != "scrypt" or ks["cipher"].get("name") != "aes-256-gcm":
        raise ValueError("Unsupported keystore encryption.")
    if ks.get("passphrase") and not passphrase:
        raise ValueError("This wallet was created with a BIP-39 passphrase — enter it.")
    key = _kdf(password, bytes.fromhex(ks["kdf"]["salt"]), int(ks["kdf"]["n"]), int(ks["kdf"]["r"]), int(ks["kdf"]["p"]))
    try:
        mnemonic = _gcm_decrypt(key, bytes.fromhex(ks["cipher"]["nonce"]), bytes.fromhex(ks["ciphertext"]),
                                _aad(ks)).decode()
    except ValueError:
        raise ValueError("Wrong password, or the keystore file was modified.")
    w = Wallet(mnemonic, passphrase, ks["network"], script=ks["script"])
    if w.fp.hex() != ks["fingerprint"] or w.path != ks["path"]:
        raise ValueError("The BIP-39 passphrase does not match this wallet (fingerprint differs).")
    return w


# ------------------------------------ PSBT analysis ---------------------------------
class _Owned:
    """Decides which scriptPubKeys belong to this account (verified by re-deriving, never trusted)."""

    def __init__(self, watch: Watch, limit: int = MAX_SCAN):
        self.w, self.limit, self.map = watch, limit, None

    def match(self, spk_bytes: bytes, hints=()):
        for der in hints:                                   # hints only save time; result is verified
            if len(der) >= 2 and der[-2] in (0, 1) and 0 <= der[-1] < HARD:
                if self.w.spk(der[-2], der[-1]).data == spk_bytes:
                    return der[-2], der[-1]
        if self.map is None:
            self.map = {self.w.spk(c, i).data: (c, i) for c in (0, 1) for i in range(self.limit)}
        return self.map.get(spk_bytes)


def _hints(scope):
    return [d.derivation for d in scope.bip32_derivations.values()]


def analyze_psbt(psbt: PSBT, watch: Watch, allow_witness_only: bool = False) -> dict:
    """Independent review of a PSBT. Returns dict with inputs, outputs, fee, errors, warnings."""
    rv = {"network": watch.network, "script": watch.script, "inputs": [], "outputs": [], "errors": [], "warnings": [],
          "fee": None, "vsize": None, "feerate": None, "external_total": 0, "txid": None}
    err, warn = rv["errors"].append, rv["warnings"].append
    tx = psbt.tx
    rv["txid"] = tx.txid().hex()
    if psbt.version not in (None, 0):
        err("PSBT version 2 is not supported.")
    owned = _Owned(watch)
    total_in = 0
    n_mine = 0
    for i, inp in enumerate(psbt.inputs):
        txin = tx.vin[i]
        info = {"txid": txin.txid.hex(), "vout": txin.vout, "value": None, "address": None, "spk": None,
                "mine": False, "chain": None, "index": None, "proven": False}
        utxo = None
        if inp.non_witness_utxo is not None:
            try:
                inp.verify()                                   # re-hash previous tx, compare with outpoint
                if txin.vout >= len(inp.non_witness_utxo.vout):
                    raise PSBTError("output index out of range")
                utxo = inp.non_witness_utxo.vout[txin.vout]
                info["proven"] = True
                w = inp.witness_utxo
                if w is not None and (w.value != utxo.value or w.script_pubkey.data != utxo.script_pubkey.data):
                    err(f"Input {i}: witness_utxo contradicts the previous transaction (tampered PSBT).")
            except PSBTError as e:
                err(f"Input {i}: previous transaction does not match the outpoint ({e}).")
        elif inp.witness_utxo is not None:
            if allow_witness_only:
                utxo = inp.witness_utxo
                warn(f"Input {i}: amount is NOT verified (no full previous tx). A malicious online machine "
                     f"could hide a huge fee. Only proceed if you trust it.")
            else:
                err(f"Input {i}: previous transaction missing — amount can't be verified "
                    f"(fee-attack protection). Rebuild the PSBT with 'include full previous transactions'.")
        else:
            err(f"Input {i}: no UTXO data at all.")
        if utxo is not None:
            info["value"] = utxo.value
            info["spk"] = utxo.script_pubkey.data
            info["address"] = spk_to_address(utxo.script_pubkey, watch.network)
            total_in += utxo.value
            hit = owned.match(utxo.script_pubkey.data, _hints(inp))
            if hit:
                if utxo.script_pubkey.script_type() != SCRIPTS[watch.script]["spk"]:
                    err(f"Input {i}: unsupported script type.")
                else:
                    info["mine"], info["chain"], info["index"] = True, hit[0], hit[1]
                    n_mine += 1
            else:
                warn(f"Input {i} does NOT belong to this wallet — it will not be signed here.")
        st = inp.sighash_type
        if st not in (None, SIGHASH.ALL, SIGHASH.DEFAULT):
            err(f"Input {i}: requests sighash type {st}; only SIGHASH_ALL is signed.")
        rv["inputs"].append(info)
    if psbt.inputs and n_mine == 0:
        err("No input of this PSBT belongs to this wallet.")

    total_out = 0
    for k, out in enumerate(tx.vout):
        spk = out.script_pubkey
        info = {"value": out.value, "address": spk_to_address(spk, watch.network), "kind": "external",
                "chain": None, "index": None, "spk_len": len(spk.data)}
        total_out += out.value
        if spk.data[:1] == b"\x6a":
            info["kind"], info["address"] = "opreturn", "OP_RETURN data: " + spk.data[1:40].hex()
            if out.value:
                warn(f"Output {k}: OP_RETURN burns {out.value} sat.")
        else:
            scope = psbt.outputs[k] if k < len(psbt.outputs) else None
            hit = owned.match(spk.data, _hints(scope) if scope else ())
            if hit and spk.script_type() == SCRIPTS[watch.script]["spk"]:
                info["chain"], info["index"] = hit
                info["kind"] = "change" if hit[0] == 1 else "self"
            if info["address"] is None:
                info["address"] = "script:" + spk.data.hex()
                warn(f"Output {k}: non-standard script.")
        if info["kind"] == "external":
            rv["external_total"] += out.value
        rv["outputs"].append(info)

    if all(i["value"] is not None for i in rv["inputs"]):
        rv["fee"] = total_in - total_out
        if rv["fee"] < 0:
            err("Outputs are larger than inputs.")
        else:
            rv["vsize"] = vsize_estimate(len(rv["inputs"]), [o["spk_len"] for o in rv["outputs"]], watch.script)
            rv["feerate"] = rv["fee"] / rv["vsize"]
            sent = max(rv["external_total"], 1)
            if rv["feerate"] > 300 or (rv["fee"] > 20000 and rv["fee"] > sent // 10):
                warn(f"HIGH FEE: {rv['fee']} sat ({rv['feerate']:.1f} sat/vB) — {100 * rv['fee'] / (sent + rv['fee']):.1f}% "
                     f"of the value leaving your wallet. Check before signing.")
            if rv["feerate"] < 1:
                warn("Fee rate is below 1 sat/vB — the transaction may never confirm.")
    if not [o for o in rv["outputs"] if o["kind"] == "change"] and rv["external_total"] and rv["fee"] is not None:
        warn("No change output: everything not sent to the recipient goes to the miner.")
    return rv


def format_review(rv: dict) -> str:
    net = rv["network"]
    tag = "  (test coins — no real value)" if NETWORKS[net]["test"] else "  ** REAL BITCOIN **"
    lines = [f"Network : {net}{tag}", f"Type    : {script_label(rv['script'])}", f"Txid    : {rv['txid']}", ""]
    lines.append(f"INPUTS ({len(rv['inputs'])})")
    for i, x in enumerate(rv["inputs"]):
        v = to_btc(x["value"]) + " BTC" if x["value"] is not None else "?"
        who = f"yours  m/…/{x['chain']}/{x['index']}" if x["mine"] else "NOT YOURS"
        lines.append(f"  #{i}  {v:>16}  {x['address'] or '?'}  [{who}]")
    lines.append("")
    lines.append(f"OUTPUTS ({len(rv['outputs'])})")
    label = {"external": "SENDING TO", "change": "change (yours)", "self": "yours (receive addr)",
             "opreturn": "OP_RETURN", "unknown": "?"}
    for i, o in enumerate(rv["outputs"]):
        extra = f" m/…/{o['chain']}/{o['index']}" if o["chain"] is not None else ""
        lines.append(f"  #{i}  {to_btc(o['value']) + ' BTC':>16}  {o['address']}   <- {label[o['kind']]}{extra}")
    lines.append("")
    if rv["fee"] is not None and rv["fee"] >= 0:
        lines.append(f"Amount leaving your wallet (to others): {to_btc(rv['external_total'])} BTC")
        lines.append(f"Fee     : {rv['fee']} sat  (~{rv['feerate']:.1f} sat/vB, est. {rv['vsize']} vB)")
    for w in rv["warnings"]:
        lines.append(f"WARNING : {w}")
    for e in rv["errors"]:
        lines.append(f"ERROR   : {e}")
    return "\n".join(lines)


# -------------------------------------- sign (offline) ------------------------------
_TAP_KEY_SIG = b"\x13"          # PSBT_IN_TAP_KEY_SIG (BIP-371). embit 0.8 doesn't parse it: it lives in .unknown


def _tap_key_sig(inp):
    v = getattr(inp, "taproot_key_sig", None) or inp.unknown.get(_TAP_KEY_SIG)
    return bytes(v) if v else None


def _set_tap_key_sig(inp, sig: bytes):
    if hasattr(inp, "taproot_key_sig"):                      # newer embit versions
        inp.taproot_key_sig = sig
    else:
        inp.unknown = dict(inp.unknown)                      # never mutate a dict shared with other inputs
        inp.unknown[_TAP_KEY_SIG] = sig


def _is_signed(inp) -> bool:
    return bool(inp.final_scriptwitness or inp.final_scriptsig or inp.partial_sigs or _tap_key_sig(inp))


def sign_psbt(psbt: PSBT, wallet: Wallet, allow_witness_only: bool = False, finalize: bool = True) -> dict:
    """Re-analyses, signs every input that belongs to the wallet. Returns dict.

    finalize=True  : inputs are finalised (final_scriptwitness / final_scriptsig) — BTCVault's own flow.
    finalize=False : \"hardware-wallet\" output exactly like a Keystone / Coldcard / Jade returns it — only the
                     signature (partial_sigs / taproot key-path sig) is added and everything else is left alone,
                     so the software wallet (UniSat, OKX, Sparrow, BlueWallet …) can finalise it itself.
                     (Finalised PSBTs make bitcoinjs-based wallets throw 'Can not finalize input'.)"""
    rv = analyze_psbt(psbt, wallet.watch, allow_witness_only)
    if rv["errors"]:
        raise ValueError("Refusing to sign:\n- " + "\n- ".join(rv["errors"]))
    script = wallet.script
    txid_before = psbt.tx.txid()
    if script == "p2tr":                                     # BIP-341 commits to ALL inputs' amounts + scripts
        all_values = [i["value"] for i in rv["inputs"]]
        all_spks = [i["spk"] for i in rv["inputs"]]
    signed = 0
    for i, inp in enumerate(psbt.inputs):
        info = rv["inputs"][i]
        if not info["mine"]:
            continue
        key = wallet.priv(info["chain"], info["index"])
        pub = key.get_public_key()

        if script == "p2tr":
            secret = key.secret                              # embit HDKey exposes the 32-byte private scalar as .secret
            if not secret:
                raise RuntimeError("Keystore holds no private key for this input.")
            d = taproot_tweak_secret(secret)
            xonly = taproot_output_key(pub.sec())
            if Script(b"\x51\x20" + xonly).data != info["spk"]:
                raise RuntimeError("Internal error: taproot key does not match the coin's script. Nothing exported.")
            ht = 1 if inp.sighash_type == SIGHASH.ALL else 0
            h = taproot_sighash(psbt.tx, all_values, all_spks, i, ht)
            try:                                             # prefer libsecp256k1 via embit, else pure Python
                sig = ec.PrivateKey(d.to_bytes(32, "big")).schnorr_sign(h).serialize()
            except (AttributeError, TypeError):
                sig = schnorr_sign(d, h, os.urandom(32))
            if not schnorr_verify(xonly, h, sig):
                raise RuntimeError("Internal error: signature failed self-check. Nothing exported.")
            tsig = sig + (bytes([ht]) if ht else b"")
            if finalize:
                inp.final_scriptwitness = Witness([tsig])
            else:
                _set_tap_key_sig(inp, tsig)
        else:
            if script == "p2pkh":
                inp.witness_utxo = None                      # must not look like a SegWit input
            else:
                inp.witness_utxo = TransactionOutput(info["value"], Script(info["spk"]))   # value is proven
                if script == "p2sh-p2wpkh":
                    inp.redeem_script = _escript.p2wpkh(pub)
            h = psbt.sighash(i, sighash=SIGHASH.ALL)
            sig = key.sign(h)
            if not pub.verify(sig, h):
                raise RuntimeError("Internal error: signature failed self-check. Nothing exported.")
            sig_b = sig.serialize() + bytes([SIGHASH.ALL])
            if not finalize:
                inp.partial_sigs.clear()
                inp.partial_sigs[pub] = sig_b
            elif script == "p2wpkh":
                inp.final_scriptwitness = Witness([sig_b, pub.sec()])
            elif script == "p2sh-p2wpkh":
                inp.final_scriptwitness = Witness([sig_b, pub.sec()])
                inp.final_scriptsig = Script(_push(_escript.p2wpkh(pub).data))
            else:
                inp.final_scriptsig = Script(_push(sig_b) + _push(pub.sec()))
        if finalize:
            inp.partial_sigs.clear()
            inp.bip32_derivations.clear()
        signed += 1
    if psbt.tx.txid() != txid_before:
        raise RuntimeError("Internal error: transaction changed while signing. Nothing exported.")
    complete = all(_is_signed(i) for i in psbt.inputs)
    raw = final_txid = None
    if complete:
        try:
            tx = extract_tx(psbt)
            raw, final_txid = tx.serialize().hex(), tx.txid().hex()
        except ValueError:
            pass                                             # e.g. multi-key partial sigs: leave to the other wallet
    # NB: for Legacy / Nested-SegWit the scriptSig is part of the txid, so it changes when signed.
    return {"psbt": psbt, "signed": signed, "complete": complete, "review": rv, "raw": raw,
            "txid": final_txid or txid_before.hex(), "finalized": finalize}


def extract_tx(psbt: PSBT) -> Transaction:
    """Final network transaction from a (fully signed) PSBT. Also finalises simple single-key partial sigs
    (P2WPKH / P2SH-P2WPKH / P2PKH / Taproot key-path) produced by other wallets."""
    tx = Transaction.parse(psbt.tx.serialize())              # fresh copy (unsigned tx has no witness)
    for i, inp in enumerate(psbt.inputs):
        wit, sig_script = inp.final_scriptwitness, inp.final_scriptsig
        if not wit and not sig_script:
            utxo = inp.utxo
            tap = _tap_key_sig(inp)
            if tap and utxo is not None and utxo.script_pubkey.script_type() == "p2tr":
                wit = Witness([bytes(tap)])
            elif len(inp.partial_sigs) == 1 and utxo is not None:
                pub, sig = next(iter(inp.partial_sigs.items()))
                spk = utxo.script_pubkey.data
                if spk == _escript.p2wpkh(pub).data:
                    wit = Witness([sig, pub.sec()])
                elif spk == _escript.p2sh(_escript.p2wpkh(pub)).data:
                    wit = Witness([sig, pub.sec()])
                    sig_script = Script(_push(_escript.p2wpkh(pub).data))
                elif spk == _escript.p2pkh(pub).data:
                    sig_script = Script(_push(sig) + _push(pub.sec()))
        if not wit and not sig_script:
            raise ValueError(f"Input {i} is not signed — this PSBT is not complete.")
        if wit:
            tx.vin[i].witness = wit
        if sig_script:
            tx.vin[i].script_sig = sig_script
    return tx


# ------------------------------- PSBT / tx text formats -----------------------------
def psbt_from_text(text: str) -> PSBT:
    """base64, hex, or ur:crypto-psbt (single string)."""
    t = "".join((text or "").split())
    if not t:
        raise ValueError("Nothing to parse.")
    if t[:3].lower() == "ur:":
        try:
            import cbor2
            import ur
        except ImportError:
            raise ValueError("UR QR needs:  pip install cbor2  (and ur.py next to btcvault.py).")
        d = ur.URDecoder()
        if not d.add(t):
            raise ValueError("That is only ONE fragment of a multi-part QR. Use 'Scan QR with camera'.")
        typ, body = d.result()
        if typ not in ("crypto-psbt", "psbt"):
            raise ValueError(f"Expected a PSBT UR but got ur:{typ}.")
        return PSBT.parse(cbor2.loads(body))
    if t.startswith("cHNidP8"):
        return PSBT.from_base64(t)
    if re.fullmatch(r"[0-9a-fA-F]+", t) and t.lower().startswith("70736274ff"):
        return PSBT.parse(bytes.fromhex(t))
    raise ValueError("Not a PSBT (expected base64 starting 'cHNidP8', hex '70736274ff…' or a ur:crypto-psbt).")


def psbt_from_file(path: str) -> PSBT:
    data = open(path, "rb").read()
    if data.startswith(b"psbt\xff"):
        return PSBT.parse(data)
    return psbt_from_text(data.decode("utf-8", "replace"))


def psbt_ur_frames(psbt: PSBT, max_fragment: int = 200):
    import cbor2
    import ur
    return ur.ur_encode_frames("crypto-psbt", cbor2.dumps(psbt.serialize()), max_fragment)




# --------------------------------------- self test ---------------------------------
_ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_VECTORS = {"p2pkh": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
            "p2sh-p2wpkh": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            "p2wpkh": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "p2tr": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"}


def _test_psbt(w: Wallet):
    """Minimal unsigned PSBT (what an online wallet would send): 1 funded input, 1 external + 1 change output."""
    watch = w.watch
    fund = Transaction(2, [TransactionInput(os.urandom(32), 0)], [TransactionOutput(150_000, watch.spk(0, 1))], 0)
    ext = Wallet(_ABANDON, "", w.network).watch.spk(0, 0)
    tx = Transaction(2, [TransactionInput(fund.txid(), 0, sequence=RBF_SEQUENCE)],
                     [TransactionOutput(100_000, ext), TransactionOutput(49_000, watch.spk(1, 0))], 0)
    psbt = PSBT(tx)
    sc, pub = psbt.inputs[0], watch.pubkey(0, 1)
    if watch.script == "p2pkh":
        sc.non_witness_utxo = fund
    else:
        sc.witness_utxo, sc.non_witness_utxo = fund.vout[0], fund
        if watch.script == "p2sh-p2wpkh":
            sc.redeem_script = _escript.p2wpkh(pub)
    if watch.script != "p2tr":
        sc.bip32_derivations[pub] = DerivationPath(watch.fp, watch.derivation(0, 1))
    return psbt


def _selftest_sign(script: str, net: str) -> str:
    w = keystore_open(keystore_create(new_mnemonic(), "selftest-password", net, script=script), "selftest-password")
    psbt = _test_psbt(w)
    rv = analyze_psbt(psbt, w.watch)
    assert not rv["errors"], rv["errors"]
    assert rv["external_total"] == 100_000 and rv["fee"] == 1_000
    assert [o for o in rv["outputs"] if o["kind"] == "change"], "change not detected"
    b64 = psbt.to_base64()
    res = sign_psbt(psbt_from_text(b64), w)
    assert res["complete"] and res["raw"]
    assert Transaction.parse(bytes.fromhex(res["raw"])).txid().hex() == res["txid"]
    hw = sign_psbt(psbt_from_text(b64), w, finalize=False)           # Keystone style: signature only
    assert hw["complete"] and not hw["finalized"]
    for i_ in hw["psbt"].inputs:
        assert not i_.final_scriptwitness and not i_.final_scriptsig
        assert i_.partial_sigs or _tap_key_sig(i_), "no signature present"
    if script != "p2pkh":                                              # fee attack: lie about the input amount
        lying = psbt_from_text(b64)
        lying.inputs[0].witness_utxo = TransactionOutput(10**9, w.watch.spk(0, 1))
        try:
            sign_psbt(lying, w); raise AssertionError("fee-attack PSBT was signed")
        except ValueError:
            pass
    thin = psbt_from_text(b64)                                         # no previous tx -> refused
    thin.inputs[0].non_witness_utxo = None
    try:
        sign_psbt(thin, w); raise AssertionError("PSBT without previous tx was signed")
    except ValueError:
        pass
    return f"sign {script_label(script):<38} OK"


def selftest() -> list:
    out = []
    for script, expected in _VECTORS.items():
        got = Wallet(_ABANDON, "", "Bitcoin Mainnet", script=script).watch.address(0, 0)
        assert got == expected, f"{script} derivation vector failed: {got}"
    out.append("BIP-44/49/84/86 derivation  OK")
    sig0 = schnorr_sign(3, bytes(32), bytes(32))
    assert sig0.hex().upper().startswith("E907831F80848D10"), "BIP-340 vector failed"
    assert schnorr_verify(_pt_mul(3)[0].to_bytes(32, "big"), bytes(32), sig0)
    out.append("BIP-340 Schnorr             OK")
    net = "Bitcoin Signet"
    ks = keystore_create(new_mnemonic(), "selftest-password", net)
    assert keystore_open(ks, "selftest-password").watch.address(0, 0) == ks["first_address"]
    for bad in ((ks, "wrong-password"), (dict(ks, network="Bitcoin Mainnet"), "selftest-password"),
                (dict(ks, script="p2tr"), "selftest-password")):
        try:
            keystore_open(*bad); raise AssertionError("bad keystore/password accepted")
        except ValueError:
            pass
    out.append("keystore scrypt+AES-GCM    OK")
    for script in SCRIPTS:
        out.append(_selftest_sign(script, net))
    try:
        import cbor2, ur
        w = Wallet(_ABANDON, "", net)
        bun = keystone_bundle(w)
        for kind in ("multi", "account"):
            d = ur.URDecoder()
            for fr in keystone_frames(bun, kind):
                d.add(fr)
            assert d.done and cbor2.loads(d.result()[1])[1] == int.from_bytes(w.fp, "big")
        psbt = _test_psbt(w)
        d = ur.URDecoder()
        for f in psbt_ur_frames(psbt, 150):
            d.add(f)
        assert d.done and psbt_from_text(ur.ur_encode_single(*d.result())).tx.txid() == psbt.tx.txid()
        out.append("Keystone pairing + ur:crypto-psbt QR  OK")
    except ImportError:
        out.append("UR QR checks SKIPPED (pip install cbor2; keep ur.py alongside)")
    return out


if __name__ == "__main__":
    for line in selftest():
        print("  " + line)
