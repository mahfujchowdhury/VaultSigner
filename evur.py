"""
evur.py — EIP-4527 helpers for ETHVault (Ethereum only).

Lets ETHVault act as a QR-only "hardware wallet" for apps that speak EIP-4527
(MetaMask QR-hardware flow, Keystone-style coordinators):

    pairing   : offline device shows   ur:crypto-hdkey       (account xpub)
    request   : coordinator shows      ur:eth-sign-request   (unsigned tx)
    response  : offline device shows   ur:eth-signature      (65-byte sig)

The generic UR/bytewords codec lives in ur.py (keep it alongside).
Requires: pip install cbor2 rlp eth_account
Signing supports EIP-1559 (type 2) and EIP-155 legacy (type 0) transactions; typed-data / personal-message
requests are refused with a clear error.
"""
import hashlib, hmac, struct, uuid
import cbor2
from collections.abc import Mapping
from ur import (crc32, bytewords_encode, bytewords_decode,      # re-exported for ethvault.py
                ur_encode_single, ur_encode_frames, URDecoder)


# --------------------------- BIP32 / EIP-4527 keys ---------------------------
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def _pub33(k: int) -> bytes:
    from eth_keys import keys
    return keys.PrivateKey(k.to_bytes(32, "big")).public_key.to_compressed_bytes()

def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def _ckd(k: int, c: bytes, i: int):
    data = (b"\x00" + k.to_bytes(32, "big") if i >= 0x80000000 else _pub33(k)) + struct.pack(">I", i)
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % _N, I[32:]

H = 0x80000000

def _flat(comps):
    """[44+H, 60+H, 0+H, 0, 0] -> [44, True, 60, True, 0, True, 0, False, 0, False]"""
    out = []
    for c in comps:
        out += [c & 0x7FFFFFFF, bool(c & H)]
    return out

def derive_account_xpub(mnemonic: str, passphrase: str = ""):
    """m/44'/60'/0' -> dict for pairing. Also returns the m/44'/60'/0'/0/0 leaf key (for Ledger-Live style entries)."""
    from eth_account.hdaccount import Mnemonic
    seed = Mnemonic.to_seed(mnemonic, passphrase)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    master_fp = _hash160(_pub33(k))[:4]
    parent_fp = master_fp
    for idx in (44 + H, 60 + H, 0 + H):
        parent_fp = _hash160(_pub33(k))[:4]
        k, c = _ckd(k, c, idx)
    out = {"pub": _pub33(k), "chain": c, "parent_fp": parent_fp, "master_fp": master_fp}
    lk, lc = k, c
    for idx in (0, 0):                                   # .../0/0
        lk, lc = _ckd(lk, lc, idx)
    out["leaf_pub"] = _pub33(lk)
    return out

# Keystone-compatible notes: wallets (MetaMask/Rabby keyring) read this to know the account type.
NOTE_STANDARD, NOTE_LEDGER_LIVE = "account.standard", "account.ledger_live"

# Pairing payload profiles. Each wallet family wants a slightly different export:
#   "classic" = the exact bytes the old working build sent (Rabby / OKX / Bitget)
#   "nexus"   = the stricter Keystone-firmware-shaped export (Keystone Nexus app, MetaMask)
PROFILE_CLASSIC, PROFILE_NEXUS = "classic", "nexus"

def _origin(comps, master_fp, depth):
    return cbor2.CBORTag(304, {1: _flat(comps), 2: int.from_bytes(master_fp, "big"), 3: depth})

def _hdkey_map(x: dict, name, note, profile=PROFILE_NEXUS) -> dict:
    """Account-level key m/44'/60'/0' with children M/0/*."""
    children = cbor2.CBORTag(304, {1: [0, False, [], False]})
    if profile == PROFILE_CLASSIC:
        head, use_info = {}, cbor2.CBORTag(305, {1: 60})                  # coin type 60 (ETH)
    else:
        head, use_info = {2: False}, cbor2.CBORTag(305, {1: 60, 2: 0})    # is-private=false, ETH mainnet
    return {**head, 3: x["pub"], 4: x["chain"], 5: use_info,
            6: _origin([44 + H, 60 + H, 0 + H], x["master_fp"], 3),
            7: children,
            8: int.from_bytes(x["parent_fp"], "big"),             # uint32 per BCR-2020-007 (NOT bytes)
            9: name, 10: note}

def hdkey_cbor(x: dict, name="Keystone", note=NOTE_STANDARD, profile=PROFILE_NEXUS) -> bytes:
    """ur:crypto-hdkey payload. profile 'nexus' for MetaMask, 'classic' for Rabby."""
    return cbor2.dumps(_hdkey_map(x, name, note, profile))

def multi_accounts_cbor(x: dict, device="Keystone", device_id=None, profile=PROFILE_NEXUS) -> bytes:
    """ur:crypto-multi-accounts payload (UNTAGGED outer map).
    'nexus'  : standard account only (Keystone Nexus app).
    'classic': standard + Ledger-Live account 0 + device id (OKX, Bitget and other Keystone-SDK wallets)."""
    fp = int.from_bytes(x["master_fp"], "big")
    if profile != PROFILE_CLASSIC:
        return cbor2.dumps({1: fp, 2: [cbor2.CBORTag(303, _hdkey_map(x, "Keystone", NOTE_STANDARD, PROFILE_NEXUS))],
                            3: device})
    std = _hdkey_map(x, "Keystone", NOTE_STANDARD, PROFILE_CLASSIC)
    ll = {3: x["leaf_pub"],
          6: _origin([44 + H, 60 + H, 0 + H, 0, 0], x["master_fp"], 5),
          9: "Keystone", 10: NOTE_LEDGER_LIVE}
    return cbor2.dumps({1: fp, 2: [cbor2.CBORTag(303, std), cbor2.CBORTag(303, ll)],
                        3: device, 4: device_id or x["master_fp"].hex()})


# ---------------------------- sign request / signature -----------------------
# EIP-4527 data-type: 1 legacy tx, 2 typed data, 3 personal message, 4 typed (EIP-2718) tx
DT_LEGACY, DT_TYPED_DATA, DT_PERSONAL, DT_TYPED = 1, 2, 3, 4

def sign_request_cbor(unsigned_typed_tx: bytes, master_fp: bytes, address: bytes = None,
                      chain_id: int = None, origin="ETHVault", req_id: bytes = None):
    """eth-sign-request keys per EIP-4527: 1 id, 2 data, 3 type, 4 chain-id, 5 derivation-path, 6 address, 7 origin."""
    rid = req_id or uuid.uuid4().bytes
    m = {1: cbor2.CBORTag(37, rid), 2: unsigned_typed_tx, 3: DT_TYPED}
    if chain_id is not None: m[4] = chain_id
    m[5] = cbor2.CBORTag(304, {1: [44, True, 60, True, 0, True, 0, False, 0, False],
                               2: int.from_bytes(master_fp, "big")})
    if address: m[6] = address
    m[7] = origin
    return cbor2.dumps(m), rid

def _rid(x) -> bytes:
    """Request id may decode as a UUID object (cbor2 knows tag 37) or a raw tag/bytes."""
    if isinstance(x, uuid.UUID): return x.bytes
    return x.value if isinstance(x, cbor2.CBORTag) else x

def _unwrap(x):
    return x.value if isinstance(x, cbor2.CBORTag) else x

def parse_sign_request(cbor_bytes: bytes) -> dict:
    m = _unwrap(cbor2.loads(cbor_bytes))
    rid = _rid(m[1])
    chain_id, kp = None, None
    for v in (m.get(4), m.get(5)):          # spec: 4=chain-id (uint), 5=keypath (tag 304); tolerate either order
        if isinstance(v, int) and not isinstance(v, bool): chain_id = v
        elif v is not None: kp = _unwrap(v)
    path, mfp = None, None
    if isinstance(kp, Mapping):                      # cbor2 >= 5.6 returns frozendict/tuples
        comps = kp.get(1, [])
        path = "m/" + "/".join(("*" if isinstance(comps[i], (list, tuple)) else str(comps[i])) + ("'" if comps[i + 1] else "")
                               for i in range(0, len(comps) - 1, 2))
        mfp = kp.get(2)
    return {"request_id": rid, "sign_data": m[2], "data_type": _unwrap(m.get(3, DT_TYPED)),
            "path": path, "master_fp": mfp, "chain_id": chain_id,
            "address": m.get(6), "origin": m.get(7)}

def signature_cbor(request_id: bytes, sig65: bytes, origin="ETHVault") -> bytes:
    return cbor2.dumps({1: cbor2.CBORTag(37, request_id), 2: sig65, 3: origin})

def parse_signature(cbor_bytes: bytes):
    m = cbor2.loads(cbor_bytes)
    return _rid(m[1]), m[2]


# -------------------------- EIP-1559 tx <-> bytes ----------------------------
def encode_unsigned_1559(tx: dict) -> bytes:
    import rlp
    def i(x): return int(x).to_bytes((int(x).bit_length() + 7) // 8, "big")
    data = bytes.fromhex(tx.get("data", "0x")[2:]) if isinstance(tx.get("data", "0x"), str) else tx["data"]
    to = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    return b"\x02" + rlp.encode([i(tx["chainId"]), i(tx["nonce"]), i(tx["maxPriorityFeePerGas"]),
                                 i(tx["maxFeePerGas"]), i(tx["gas"]), to, i(tx["value"]), data, []])

def decode_unsigned_1559(b: bytes) -> dict:
    import rlp
    from eth_utils import to_checksum_address
    if not b or b[0] != 2:
        raise ValueError("Only EIP-1559 (type 2) transactions are supported by ETHVault.")
    f = rlp.decode(b[1:], strict=True)
    if len(f) != 9: raise ValueError("Unexpected transaction field count.")
    n = lambda x: int.from_bytes(x, "big")
    if f[8]: raise ValueError("Transactions with an access list are not supported.")
    return {"chainId": n(f[0]), "nonce": n(f[1]), "maxPriorityFeePerGas": n(f[2]),
            "maxFeePerGas": n(f[3]), "gas": n(f[4]),
            "to": to_checksum_address(f[5]) if f[5] else None,
            "value": n(f[6]), "data": "0x" + f[7].hex(), "type": 2}

# ---- legacy (type 0, EIP-155) transactions: eth-sign-request data-type 1 ----
def encode_unsigned_legacy(tx: dict) -> bytes:
    """EIP-155 signing preimage: rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])."""
    import rlp
    def i(x): return int(x).to_bytes((int(x).bit_length() + 7) // 8, "big")
    data = bytes.fromhex(tx.get("data", "0x")[2:]) if isinstance(tx.get("data", "0x"), str) else tx["data"]
    to = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    return rlp.encode([i(tx["nonce"]), i(tx["gasPrice"]), i(tx["gas"]), to, i(tx["value"]), data,
                       i(tx["chainId"]), b"", b""])

def decode_unsigned_legacy(b: bytes) -> dict:
    import rlp
    from eth_utils import to_checksum_address
    f = rlp.decode(b, strict=True)
    if len(f) == 6:
        raise ValueError("This legacy transaction has no chain id (pre-EIP-155), so it could be replayed on "
                         "other networks. ETHVault refuses to sign it.")
    if len(f) != 9 or f[7] != b"" or f[8] != b"":
        raise ValueError("Unexpected legacy transaction layout.")
    n = lambda x: int.from_bytes(x, "big")
    return {"chainId": n(f[6]), "nonce": n(f[0]), "gasPrice": n(f[1]), "gas": n(f[2]),
            "to": to_checksum_address(f[3]) if f[3] else None,
            "value": n(f[4]), "data": "0x" + f[5].hex(), "type": 0}

def sig_from_signed_legacy(signed, chain_id: int) -> bytes:
    """r || s || v with the full EIP-155 v (= recid + 35 + 2*chainId), minimal big-endian bytes.
    This is what Keystone-SDK wallets feed straight into the signed legacy transaction."""
    v = int(signed.v)
    return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")

def sig65_from_signed(signed) -> bytes:
    return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([signed.v & 1])


def assemble_signed_1559(tx: dict, sig65: bytes) -> str:
    """Coordinator side: unsigned tx + 65-byte signature -> raw signed tx hex (0x02...)."""
    import rlp
    def i(x): return int(x).to_bytes((int(x).bit_length() + 7) // 8, "big")
    data = bytes.fromhex(tx.get("data", "0x")[2:])
    to = bytes.fromhex(tx["to"][2:]) if tx.get("to") else b""
    v = sig65[64] - 27 if sig65[64] >= 27 else sig65[64]
    r, s = int.from_bytes(sig65[:32], "big"), int.from_bytes(sig65[32:64], "big")
    raw = b"\x02" + rlp.encode([i(tx["chainId"]), i(tx["nonce"]), i(tx["maxPriorityFeePerGas"]),
                                i(tx["maxFeePerGas"]), i(tx["gas"]), to, i(tx["value"]), data, [], i(v), i(r), i(s)])
    return "0x" + raw.hex()


# ------------------------- signer-side helpers (used by GUI) -----------------
def validate_sign_request(text: str):
    """Single-part UR text -> (request dict, tx dict). tx["type"] is 2 (EIP-1559) or 0 (legacy EIP-155).
    Raises ValueError with a user-readable reason."""
    d = URDecoder()
    if not d.add(text):
        raise ValueError("This UR is only one fragment of a multi-part QR. Use 'Scan QR with camera' "
                         "so every frame is collected.")
    t, body = d.result()
    if t != "eth-sign-request":
        raise ValueError(f"Expected ur:eth-sign-request but got ur:{t}")
    rq = parse_sign_request(body)
    if rq["data_type"] == DT_TYPED:
        tx = decode_unsigned_1559(rq["sign_data"])
        if encode_unsigned_1559(tx) != rq["sign_data"]:
            raise ValueError("Transaction encoding is non-canonical; refusing to sign.")
    elif rq["data_type"] == DT_LEGACY:
        tx = decode_unsigned_legacy(rq["sign_data"])
        if encode_unsigned_legacy(tx) != rq["sign_data"]:
            raise ValueError("Transaction encoding is non-canonical; refusing to sign.")
    else:
        kind = {DT_TYPED_DATA: "typed-data (EIP-712)", DT_PERSONAL: "personal-message"}.get(
            rq["data_type"], f"data-type {rq['data_type']}")
        raise ValueError(f"ETHVault signs only transactions (EIP-1559 or legacy); this request is a {kind}.")
    if rq["chain_id"] is not None and rq["chain_id"] != tx["chainId"]:
        raise ValueError("chainId in the request does not match the chainId inside the transaction.")
    return rq, tx


def sign_request_with_key(rq: dict, tx: dict, key: bytes):
    """Sign after checking the key is the account the request asks for. Returns (sig65, address)."""
    from eth_account import Account
    from eth_keys import keys
    from eth_utils import keccak
    acct = Account.from_key(key)
    want = rq.get("address")
    if want:
        if acct.address.lower() != "0x" + bytes(want).hex():
            raise ValueError(f"The request is for 0x{bytes(want).hex()} but this keystore is {acct.address}.")
    elif rq.get("path") not in (None, "m/44'/60'/0'/0/0"):
        raise ValueError(f"The request asks for {rq['path']}; this keystore only holds the m/44'/60'/0'/0/0 key.")
    fields = {k: v for k, v in tx.items() if k != "type" and v is not None}
    signed = Account.sign_transaction(fields, key)
    if tx.get("type") == 0:
        sig = sig_from_signed_legacy(signed, tx["chainId"])
        rec_id = int(signed.v) - 35 - 2 * tx["chainId"]
        if rec_id not in (0, 1):
            raise ValueError("Internal check failed: unexpected EIP-155 v. Not exporting.")
    else:
        sig = sig65_from_signed(signed)
        rec_id = sig[64]
    rec = keys.Signature(vrs=(rec_id, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"))
                         ).recover_public_key_from_msg_hash(keccak(rq["sign_data"])).to_checksum_address()
    if rec != acct.address:
        raise ValueError("Internal check failed: signature does not verify over the request data. Not exporting.")
    return sig, acct.address