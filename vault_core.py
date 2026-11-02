"""
vault_core.py — ETHVault Lite logic. NO GUI, NO network code.

Everything the offline signer does lives here so the same module can sit behind
a Tkinter window today and an Android UI (Kivy / Chaquopy / BeeWare) tomorrow:

    create_keystore / restore_keystore   (old tab 1)
    review_request / sign_request        (old tab 3)
    pairing_frames                       (old tab 6)

Needs: eth_account, cbor2, rlp   (+ evur.py and ur.py next to this file)
"""
import json, os, sys
from decimal import Decimal

from eth_account import Account
Account.enable_unaudited_hdwallet_features()

import evur

GWEI, WEI = 10**9, 10**18

# ------------------------------- networks ----------------------------------
# Used ONLY to name the chain / coin on the review screen. No RPC: this app never goes online.
NETWORKS = {
    "Ethereum Mainnet":  {"chain_id": 1,        "symbol": "ETH",  "testnet": False},
    "BNB Smart Chain":   {"chain_id": 56,       "symbol": "BNB",  "testnet": False},
    "Polygon PoS":       {"chain_id": 137,      "symbol": "POL",  "testnet": False},
    "Arbitrum One":      {"chain_id": 42161,    "symbol": "ETH",  "testnet": False},
    "Optimism":          {"chain_id": 10,       "symbol": "ETH",  "testnet": False},
    "Base":              {"chain_id": 8453,     "symbol": "ETH",  "testnet": False},
    "Avalanche C-Chain": {"chain_id": 43114,    "symbol": "AVAX", "testnet": False},
    "Sepolia Testnet":   {"chain_id": 11155111, "symbol": "ETH",  "testnet": True},
    "Holesky Testnet":   {"chain_id": 17000,    "symbol": "ETH",  "testnet": True},
}


def _load_user_networks(path=None):
    """Optional networks.json next to this file adds/overrides networks, e.g.
    {"Gnosis": {"chain_id": 100, "symbol": "xDAI", "testnet": false}}   (all-or-nothing)"""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "networks.json")
    if not os.path.exists(path):
        return
    try:
        ok = {}
        for name, v in json.load(open(path)).items():
            cid, sym = int(v["chain_id"]), str(v["symbol"])[:8]
            if cid <= 0 or not sym:
                raise ValueError(f"bad entry '{name}'")
            ok[str(name)] = {"chain_id": cid, "symbol": sym, "testnet": bool(v.get("testnet", False))}
        NETWORKS.update(ok)
    except Exception as e:
        print(f"networks.json ignored: {e}", file=sys.stderr)


_load_user_networks()


def net_of(chain_id):
    return next((n for n, v in NETWORKS.items() if v["chain_id"] == chain_id), None)


def sym_for(chain_id) -> str:
    n = net_of(chain_id)
    return NETWORKS[n]["symbol"] if n else "native coin"


def is_real(chain_id) -> bool:
    """True for mainnets AND unknown chains (anything not a known testnet is treated as real money)."""
    n = net_of(chain_id)
    return not (n and NETWORKS[n].get("testnet"))


def real_banner(chain_id) -> str:
    return (f"*** REAL FUNDS — {net_of(chain_id) or 'UNKNOWN NETWORK'} (chainId {chain_id}) ***\n\n"
            if is_real(chain_id) else "")


# --------------------------- review-screen helpers ---------------------------
# USDT/USDC have 18 decimals on BNB Chain but 6 on Ethereum. Unlisted tokens are shown as UNKNOWN with raw units.
KNOWN_TOKENS = {
    (1,  "0xdac17f958d2ee523a2206206994597c13d831ec7"): ("USDT", 6),
    (1,  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): ("USDC", 6),
    (56, "0x55d398326f99059ff775485246999027b3197955"): ("USDT", 18),
    (56, "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"): ("USDC", 18),
}


def describe_calldata(chain_id, to, data) -> str:
    """Human-readable decode of ERC-20 transfer / approve / transferFrom, so token, recipient and amount
    are visible BEFORE signing."""
    try:
        from eth_utils import to_checksum_address
        raw = bytes.fromhex((data or "0x")[2:])
        if len(raw) < 4 or not to:
            return ""
        sel, body = raw[:4].hex(), raw[4:]
        kinds = {"a9059cbb": ("TRANSFER", 2), "095ea7b3": ("APPROVE spending of", 2), "23b872dd": ("TRANSFER-FROM", 3)}
        if sel not in kinds:
            return "Call    : unrecognised contract method 0x" + sel + " — cannot show what it does\n"
        name, nwords = kinds[sel]
        if len(body) != 32 * nwords:
            return "Call    : malformed token call — DO NOT SIGN\n"
        w = [body[i:i + 32] for i in range(0, len(body), 32)]
        addr = lambda x: to_checksum_address("0x" + x[12:].hex())
        amount = int.from_bytes(w[-1], "big")
        tok = KNOWN_TOKENS.get((chain_id, to.lower()))
        if tok:
            sym, dec = tok
            amt = f"{(Decimal(amount) / Decimal(10) ** dec).normalize():f} {sym}"
            who = f"Token   : {sym} (known contract, {dec} decimals) {to}\n"
        else:
            amt = f"{amount} raw units (decimals unknown)"
            who = f"Token   : UNKNOWN token contract {to} — verify it on the block explorer!\n"
        if sel == "a9059cbb":
            line = f"Action  : {name} {amt}\nTo      : {addr(w[0])}   <-- the real recipient\n"
        elif sel == "095ea7b3":
            unl = "   *** UNLIMITED allowance ***" if amount >= 2**255 else ""
            line = f"Action  : {name} {amt} by {addr(w[0])}{unl}\n"
        else:
            line = f"Action  : {name} {amt}\nFrom    : {addr(w[0])}\nTo      : {addr(w[1])}\n"
        return who + line
    except Exception as e:
        return f"Call    : could not decode ({e})\n"


def gwei_str(wei) -> str:
    t = f"{Decimal(wei) / Decimal(GWEI):.4f}".rstrip("0").rstrip(".")
    return t or "0"


def to_eth(wei) -> str:
    return f"{(Decimal(wei) / Decimal(WEI)).normalize():f}"


# ------------------------------ (old) TAB 1 --------------------------------
def create_keystore(password: str, with_seed: bool):
    """New wallet -> (address, keystore_dict, mnemonic_or_None). Keystore is scrypt-encrypted (v3)."""
    if with_seed:
        acct, mnemonic = Account.create_with_mnemonic(num_words=24)
    else:
        acct, mnemonic = Account.create(), None
    return acct.address, Account.encrypt(acct.key, password), mnemonic


def clean_words(text: str) -> str:
    return " ".join(text.lower().split())


def check_seed_length(words: str) -> bool:
    return len(words.split()) in (12, 15, 18, 21, 24)


def restore_keystore(words: str, password: str):
    """Seed phrase -> (address, keystore_dict) for m/44'/60'/0'/0/0."""
    acct = Account.from_mnemonic(words)
    return acct.address, Account.encrypt(acct.key, password)


def keystore_filename(addr: str) -> str:
    return f"UTC--{addr[2:10]}.keystore.json"


def password_problem(p1: str, p2: str):
    """None if fine, else a message."""
    if len(p1) < 8:
        return "Password must be at least 8 characters."
    if p1 != p2:
        return "Passwords do not match."
    return None


# ------------------------------ (old) TAB 3 --------------------------------
def review_request(text: str):
    """ur:eth-sign-request text -> (request dict, tx dict, review text, network_known).
    Raises ValueError with a user-readable reason (typed-data, personal message, bad encoding, ...)."""
    rq, tx = evur.validate_sign_request(text)
    cid = tx["chainId"]
    net, sym, data = net_of(cid), sym_for(cid), tx.get("data", "0x")
    if tx.get("type") == 0:                                        # legacy (EIP-155)
        fee = (f"Gas price: {gwei_str(tx['gasPrice'])} gwei  (legacy transaction)\n"
               f"Max cost: {to_eth(tx['value'] + tx['gas'] * tx['gasPrice'])} {sym}\n")
    else:                                                          # EIP-1559
        fee = (f"Max fee : {gwei_str(tx['maxFeePerGas'])} gwei  (tip {gwei_str(tx['maxPriorityFeePerGas'])})\n"
               f"Max cost: {to_eth(tx['value'] + tx['gas'] * tx['maxFeePerGas'])} {sym}\n")
    frm = ("0x" + bytes(rq["address"]).hex()) if rq.get("address") else "(this keystore)"
    review = (real_banner(cid) + "Request from: " + str(rq.get("origin") or "unknown app") + "\n"
              "Please verify EVERY line before signing:\n\n"
              f"Network : {net or 'UNKNOWN network'}  (chainId {cid})\n"
              f"From    : {frm}\n"
              f"To      : {tx['to'] or '(CONTRACT CREATION)'}\n"
              f"Amount  : {to_eth(tx['value'])} {sym}\n"
              f"Nonce   : {tx['nonce']}   Gas: {tx['gas']}\n"
              + fee +
              f"Data    : {data[:80]}{'  <-- CONTRACT CALL' if data not in ('0x', '') else ''}\n"
              + describe_calldata(cid, tx["to"], data))
    if not net:
        review += "\nWARNING: this chainId is not a network ETHVault knows.\n"
    return rq, tx, review, net is not None


def load_keystore(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def sign_request(rq: dict, tx: dict, keystore: dict, password: str):
    """Decrypt keystore, sign, self-verify. Returns (QR frame strings for ur:eth-signature, signer address).
    Raises on wrong password / wrong account / failed self-check."""
    key = Account.decrypt(keystore, password)                      # scrypt: ~1-2 s
    try:
        sig, addr = evur.sign_request_with_key(rq, tx, key)
    finally:
        key = b"\x00" * len(key)
        del key
    frames = evur.ur_encode_frames("eth-signature", evur.signature_cbor(rq["request_id"], sig), 120)
    return frames, addr


# ------------------------------ (old) TAB 6 --------------------------------
# (label, UR type, payload profile, QR fragment size)
PAIR_CHOICES = [
    ("Keystone Nexus app   (crypto-multi-accounts)",             "multi", "nexus",   100),
    ("OKX / Bitget         (crypto-multi-accounts, classic)",    "multi", "classic", 200),
    ("MetaMask             (crypto-hdkey)",                      "hdkey", "nexus",   100),
    ("Rabby                (crypto-hdkey, classic)",             "hdkey", "classic", 200),
]

PAIR_HELP = ("Compare the address above with your keystore's address BEFORE pairing.\n"
             "Scan the QR in the wallet:  Keystone Nexus -> Connect | OKX / Bitget -> Keystone | "
             "MetaMask -> QR-based | Rabby -> Keystone.\n"
             "If one entry is rejected, try the other entry of the same wallet family.\n"
             "Later the wallet shows a request QR: scan it on the Sign tab, sign, and show the signature QR back.")


def pairing_frames(words: str, passphrase: str, choice: int):
    """Seed phrase -> (QR frames, first-account address, master fingerprint hex)."""
    _label, kind, profile, frag = PAIR_CHOICES[choice]
    x = evur.derive_account_xpub(words, passphrase)
    addr = Account.from_mnemonic(words, passphrase=passphrase).address
    if kind == "multi":
        frames = evur.ur_encode_frames("crypto-multi-accounts", evur.multi_accounts_cbor(x, profile=profile), frag)
    else:
        frames = evur.ur_encode_frames("crypto-hdkey", evur.hdkey_cbor(x, profile=profile), frag)
    return frames, addr, x["master_fp"].hex()


# ------------------------------- self-test ---------------------------------
def selftest():
    import cbor2
    from eth_keys import keys
    print("ETHVault Lite self-test (no network, no GUI)…")

    # tab 1: create / restore
    addr, ks, mn = create_keystore("selftest-password", True)
    assert len(mn.split()) == 24 and Account.decrypt(ks, "selftest-password")
    a2, ks2 = restore_keystore(mn, "another-password")
    assert a2 == addr, "restore address mismatch"
    print(f"  create + restore keystore      OK  ({addr})")

    # tab 6: pairing — the exported account key must derive the same first address as the seed
    for i, (label, *_r) in enumerate(PAIR_CHOICES):
        frames, paddr, xfp = pairing_frames(mn, "", i)
        assert paddr == addr and frames
    x = evur.derive_account_xpub(mn)
    assert keys.PublicKey.from_compressed_bytes(x["leaf_pub"]).to_checksum_address() == addr
    print(f"  pairing QR (4 wallet profiles) OK  (xfp {xfp})")

    # tab 3: EIP-1559 request -> review -> sign -> raw tx recovers to signer
    tx = {"chainId": 11155111, "nonce": 3, "maxPriorityFeePerGas": GWEI, "maxFeePerGas": 30 * GWEI,
          "gas": 21000, "to": "0x000000000000000000000000000000000000dEaD", "value": 10**16, "data": "0x", "type": 2}
    req, _ = evur.sign_request_cbor(evur.encode_unsigned_1559(tx), x["master_fp"],
                                    bytes.fromhex(addr[2:]), tx["chainId"])
    text = evur.ur_encode_frames("eth-sign-request", req, 1000)[0].lower()
    rq, dtx, review, known = review_request(text)
    assert known and "Sepolia" in review and "0.01 ETH" in review
    frames, signer = sign_request(rq, dtx, ks, "selftest-password")
    d = evur.URDecoder(); assert d.add(frames[0].lower())
    _t, body = d.result(); rid, sig = evur.parse_signature(body)
    assert rid == rq["request_id"] and signer == addr
    raw = evur.assemble_signed_1559(dtx, sig)
    assert Account.recover_transaction(raw) == addr
    print("  EIP-1559 review + sign         OK")

    # tab 3: legacy EIP-155 request (what some Keystone-SDK wallets send)
    ltx = {"chainId": 56, "nonce": 0, "gasPrice": 3 * GWEI, "gas": 21000,
           "to": "0x000000000000000000000000000000000000dEaD", "value": 10**15, "data": "0x"}
    lreq = cbor2.dumps({1: cbor2.CBORTag(37, b"\x11" * 16), 2: evur.encode_unsigned_legacy(ltx), 3: evur.DT_LEGACY,
                        4: 56, 5: cbor2.CBORTag(304, {1: [44, True, 60, True, 0, True, 0, False, 0, False],
                                                      2: int.from_bytes(x["master_fp"], "big")}),
                        6: bytes.fromhex(addr[2:]), 7: "selftest"})
    rq, dtx, review, known = review_request(evur.ur_encode_frames("eth-sign-request", lreq, 1000)[0].lower())
    assert "legacy" in review and "REAL FUNDS" in review
    frames, signer = sign_request(rq, dtx, ks, "selftest-password")
    assert signer == addr
    print("  legacy EIP-155 review + sign   OK")

    # safety: wrong password, typed-data refusal, wrong account
    try:
        sign_request(rq, dtx, ks, "wrong-password"); raise SystemExit("wrong password was accepted!")
    except ValueError:
        pass
    pm = cbor2.dumps({1: cbor2.CBORTag(37, b"\x22" * 16), 2: b"hello", 3: evur.DT_PERSONAL})
    try:
        review_request(evur.ur_encode_frames("eth-sign-request", pm, 1000)[0].lower())
        raise SystemExit("personal message was accepted!")
    except ValueError:
        pass
    other, _ = Account.create(), None
    rq_bad = dict(rq, address=bytes.fromhex(other.address[2:]))
    try:
        sign_request(rq_bad, dtx, ks, "selftest-password"); raise SystemExit("wrong account was accepted!")
    except ValueError:
        pass
    print("  wrong pw / typed-data / wrong account refused  OK")
    print("ALL TESTS PASSED ✔")


if __name__ == "__main__":
    selftest()
