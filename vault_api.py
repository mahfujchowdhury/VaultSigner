"""
vault_api.py — the single object the HTML UI talks to.  NO GUI, NO network.

    api = VaultApi(data_dir)
    reply_json = api.dispatch("unlock", '{"pin":"123456"}')      # -> '{"ok":true,"data":{...}}'

Every UI action is a method named m_<name>.  Hosts only need to forward (method, json) -> json:
    desktop test : run_vault.py (pywebview)            Android : Chaquopy @JavascriptInterface (see README.md)

Glue between: vault_store (PIN + encrypted DB)  |  btcv_lite (Bitcoin)  |  vault_core + evur + ur (Ethereum / EVM)
"""
import json, os, re, secrets, threading, time

try:
    import btcv_lite as btcv
    HAS_BTC, BTC_ERR = True, None
except Exception as _e:                                   # embit / pycryptodome missing
    btcv, HAS_BTC, BTC_ERR = None, False, _e
try:
    import vault_core as core
    import evur
    HAS_ETH, ETH_ERR = True, None
except Exception as _e:                                   # eth_account / cbor2 / rlp missing
    core, evur, HAS_ETH, ETH_ERR = None, None, False, _e
try:
    import ur
    HAS_UR = True
except Exception:
    ur, HAS_UR = None, False
try:
    import qrcode
    HAS_QR = True
except Exception:
    qrcode, HAS_QR = None, False

import vault_store as vs

BTC, ETH = "Bitcoin", "Ethereum"
# UI network key -> (engine, bitcoin network name)
NETS = {"btc": (BTC, "Bitcoin Mainnet"), "btct": (BTC, "Bitcoin Testnet3"), "btct4": (BTC, "Bitcoin Testnet4"),
        "btcs": (BTC, "Bitcoin Signet"), "eth": (ETH, None), "bnb": (ETH, None)}
COLORS = ["var(--signal)", "var(--secure)", "var(--ember)", "#9C2F61", "#8697FF", "#F6851B"]
BTC_TYPES = [("p2wpkh", "p2wpkh"), ("p2sh", "p2sh-p2wpkh"), ("p2tr", "p2tr"), ("p2pkh", "p2pkh")]   # (UI key, engine script)
_SPK_TO_SCRIPT = {"p2wpkh": "p2wpkh", "p2tr": "p2tr", "p2sh": "p2sh-p2wpkh", "p2pkh": "p2pkh"}


class ApiError(Exception):
    def __init__(self, msg, code="error", **extra):
        super().__init__(msg)
        self.code, self.extra = code, extra


# ------------------------------ pure helpers --------------------------------
def detect_request(text: str) -> str:
    t = "".join((text or "").split())
    if not t:
        raise ValueError("Nothing scanned yet.")
    low = t.lower()
    if low.startswith("ur:"):
        typ = low[3:].split("/")[0]
        if typ == "eth-sign-request":
            return ETH
        if typ in ("crypto-psbt", "psbt"):
            return BTC
        raise ValueError(f"Unsupported QR type ur:{typ}. This signer handles ur:eth-sign-request (Ethereum / EVM) "
                         f"and ur:crypto-psbt (Bitcoin).")
    if t.startswith("cHNidP8") or (re.fullmatch(r"[0-9a-fA-F]+", t) and low.startswith("70736274ff")):
        return BTC
    raise ValueError("Not recognised. Expected a ur:eth-sign-request, a ur:crypto-psbt, or a PSBT "
                     "(base64 'cHNidP8…' / hex '70736274ff…').")


def evf_frames(payload: str, size: int = 400):
    """Long plain text -> 'EVF:i/n:' frames for the animated-QR viewer (Vault-to-Vault format)."""
    if len(payload) <= size:
        return [payload]
    n = -(-len(payload) // size)
    return [f"EVF:{i + 1}/{n}:{payload[i * size:(i + 1) * size]}" for i in range(n)]


class Collector:
    """Feed scanned QR strings in; returns the complete text once every fragment has arrived.
    Single + multipart UR (any type) and 'EVF:' frames."""

    def __init__(self):
        self.dec = ur.URDecoder() if HAS_UR else None
        self.evf = {}

    def feed(self, t: str):
        t = t.strip()
        if t[:3].lower() == "ur:":
            if not HAS_UR:
                raise ValueError("UR QR needs cbor2 (pip install cbor2).")
            if self.dec.add(t):
                ty, body = self.dec.result()
                return ur.ur_encode_single(ty, body), None
            n, tot = self.dec.progress()
            return None, (n, tot)
        if t.startswith("EVF:"):
            _, pos, ch = t.split(":", 2)
            i, n = map(int, pos.split("/"))
            self.evf[i] = ch
            if len(self.evf) == n:
                return "".join(self.evf[k] for k in range(1, n + 1)), None
            return None, (len(self.evf), n)
        return t, None


def qr_svg(text: str) -> str:
    """Self-contained black-on-white SVG (own quiet zone) — readable by any scanner regardless of UI theme."""
    if not HAS_QR:
        raise ApiError("QR rendering needs:  pip install qrcode", "no_qr")
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0, box_size=1)
    q.add_data(text)
    q.make(fit=True)
    m, b = q.get_matrix(), 2
    n, d = len(m), []
    for y, row in enumerate(m):
        x = 0
        while x < n:
            if row[x]:
                x0 = x
                while x < n and row[x]:
                    x += 1
                d.append(f"M{x0 + b} {y + b}h{x - x0}v1h-{x - x0}z")
            else:
                x += 1
    s = n + 2 * b
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" shape-rendering="crispEdges">'
            f'<rect width="{s}" height="{s}" fill="#fff"/><path d="{"".join(d)}" fill="#000"/></svg>')


def weak_pin(pin: str):
    if not re.fullmatch(r"\d{6}", pin or ""):
        return "PIN must be exactly 6 digits."
    if len(set(pin)) == 1:
        return "That PIN is too easy to guess (all the same digit)."
    if pin in "01234567890" or pin in "09876543210":
        return "That PIN is too easy to guess (a straight sequence)."
    if pin[:3] == pin[3:] or pin[:2] * 3 == pin:
        return "That PIN is too easy to guess (a repeating pattern)."
    return None


def _ago(ts):
    d = max(0, int(time.time() - ts))
    for n, u in ((86400, "d"), (3600, "h"), (60, "m")):
        if d >= n:
            return f"{d // n}{u} ago"
    return "just now"


def _usd(v):
    return "${:,.2f}".format(v)


# ----------------------------------- API ------------------------------------
class VaultApi:
    def __init__(self, data_dir, host=None, device=None):
        self.store = vs.VaultStore(os.path.join(data_dir, "vault.db"), device)
        self.host = host                                  # optional: .save_file(name, bytes|str) -> path or None
        self._lock = threading.RLock()
        self._draft = None                                # new/imported seed waiting for a PIN (memory only)
        self._pending = None                              # reviewed request waiting for PIN
        self._signed = None                               # last signing result (for "save file")
        self._info_cache = {}
        self._collector = Collector()
        self._last = time.monotonic()

    # ---------------- dispatch ----------------
    _OPEN = {"status", "unlock", "setup_check", "touch", "new_wallet", "check_quiz", "import_wallet",
             "commit_draft", "cancel_draft", "reset_vault"}          # callable while locked

    def dispatch(self, method: str, args=None) -> str:
        with self._lock:
            try:
                if isinstance(args, str):
                    args = json.loads(args or "{}")
                args = args or {}
                fn = getattr(self, "m_" + str(method), None)
                if fn is None:
                    raise ApiError(f"Unknown method '{method}'", "bad_method")
                if method not in self._OPEN:
                    self._need_unlocked()
                if method != "touch":
                    self._last = time.monotonic()
                return json.dumps({"ok": True, "data": fn(**args)})
            except vs.Wiped as e:
                self._reset_session()
                return json.dumps({"ok": False, "error": str(e), "code": "wiped"})
            except vs.BadPin as e:
                return json.dumps({"ok": False, "error": str(e), "code": "bad_pin", "attempts_left": e.left})
            except vs.Locked as e:
                return json.dumps({"ok": False, "error": str(e), "code": "locked"})
            except ApiError as e:
                return json.dumps({"ok": False, "error": str(e), "code": e.code, **e.extra})
            except Exception as e:                        # never echo arguments (they can contain secrets)
                return json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}", "code": "error"})

    def _need_unlocked(self):
        s = self.store.settings().get("autolock", 60) if self.store.unlocked else 0
        if self.store.unlocked and s and time.monotonic() - self._last > s + 5:
            self.m_lock()
        if not self.store.unlocked:
            raise vs.Locked("Vault is locked.")

    def _reset_session(self):
        self._draft = self._pending = self._signed = None
        self._info_cache.clear()
        self._collector = Collector()

    # ---------------- wallet info ----------------
    def _secret(self, wid):
        s = self.store.get_secret(wid)
        return s["mnemonic"], s.get("passphrase", "")

    def _info(self, wid):
        if wid not in self._info_cache:
            mn, pp = self._secret(wid)
            self._info_cache[wid] = self._derive_info(mn, pp)
        return self._info_cache[wid]

    @staticmethod
    def _derive_info(mn, pp):
        i = {}
        if HAS_BTC:
            w = btcv.Wallet(mn, pp, "Bitcoin Mainnet")
            i["btc"], i["fp"] = w.watch.address(0, 0), w.fp.hex()
            i["bt"] = {ui: (i["btc"] if eng == "p2wpkh" else
                            btcv.Wallet(mn, pp, "Bitcoin Mainnet", script=eng).watch.address(0, 0)) for ui, eng in BTC_TYPES}
            i["btct"] = btcv.Wallet(mn, pp, "Bitcoin Testnet3").watch.address(0, 0)
        if HAS_ETH:
            from eth_account import Account
            i["eth"] = i["bnb"] = Account.from_mnemonic(mn, passphrase=pp).address
            if "fp" not in i:
                i["fp"] = evur.derive_account_xpub(mn, pp)["master_fp"].hex()
        return i

    def _wallet_view(self, w):
        info = self._info(w["id"])
        sync = self.store.get_sync(w["id"])
        h = {k: [v.get("amt", 0), v.get("usd", 0)] for k, v in (sync or {}).get("balances", {}).items()}
        tot = sum(v[1] for v in h.values())
        names = [k.upper() for k in ("btc", "eth", "bnb") if k in info]
        ty = w.get("btc_type", 0)
        return {"id": w["id"], "n": w["name"], "c": w["color"], "fp": info.get("fp"),
                "bt": info.get("bt", {}), "ty": ty if ty in range(len(BTC_TYPES)) else 0,
                "a": {k: info[k] for k in ("btc", "btct", "eth", "bnb") if k in info},
                "h": h, "b": _usd(tot), "s": f"Synced {_ago(sync['updated'])}" if sync else "Never synced",
                "w": " · ".join(names)}

    def _state(self):
        st = self.store
        out = {"initialized": st.initialized(), "unlocked": st.unlocked, "wallets": [],
               "settings": st.settings() if st.initialized() else dict(vs.DEFAULT_SETTINGS),
               "caps": {"btc": HAS_BTC, "eth": HAS_ETH, "ur": HAS_UR, "qr": HAS_QR,
                        "btc_err": str(BTC_ERR) if BTC_ERR else None, "eth_err": str(ETH_ERR) if ETH_ERR else None,
                        "save": bool(self.host and hasattr(self.host, "save_file"))},
               "attempts_left": st.attempts_left()}
        if st.unlocked:
            out["wallets"] = [self._wallet_view(w) for w in st.list_wallets()]
        return out

    # ---------------- session / PIN ----------------
    def m_status(self):
        if self.store.unlocked:
            try:
                self._need_unlocked()
            except vs.Locked:
                pass
        return self._state()

    def m_touch(self):
        return {"unlocked": self.store.unlocked}

    def m_setup_check(self, pin):
        return {"problem": weak_pin(pin)}

    def m_unlock(self, pin):
        self.store.unlock(pin)
        self._last = time.monotonic()
        return self._state()

    def m_lock(self):
        self.store.lock()
        self._reset_session()
        return self._state()

    def m_verify_pin(self, pin):
        self.store.verify_pin(pin)
        return {"ok": True}

    def m_save_text(self, name, text):
        if not (self.host and hasattr(self.host, "save_file")):
            raise ApiError("This host has no file dialog — use Copy instead.", "no_host")
        return {"path": self.host.save_file(os.path.basename(name), text)}

    def m_change_pin(self, old, new):
        p = weak_pin(new)
        if p:
            raise ApiError(p, "weak_pin")
        self.store.change_pin(old, new)
        return {"changed": True}

    def m_set_setting(self, key, value):
        if key == "autolock" and value in (0, 30, 60, 300):
            pass
        elif key == "max_attempts" and value in (0, 5, 10):
            pass
        elif key == "btc_hw_mode" and isinstance(value, bool):
            pass
        else:
            raise ApiError("Invalid setting.", "bad_setting")
        return self.store.set_settings(**{key: value})

    def m_reset_vault(self):
        """'Forgot PIN': erase the vault (restorable only from the seed phrase). The UI asks for confirmation first."""
        self.store.wipe()
        self._reset_session()
        return self._state()

    def m_wipe(self, pin):
        self.store.verify_pin(pin)
        self.store.wipe()
        self._reset_session()
        return self._state()

    # ---------------- create / import ----------------
    def m_new_wallet(self, passphrase="", name=""):
        if not (HAS_BTC or HAS_ETH):
            raise ApiError("No chain engine is available.", "no_engine")
        if HAS_BTC:
            mn = btcv.new_mnemonic(24)
        else:
            from eth_account import Account
            mn = Account.create_with_mnemonic(num_words=24)[1]
        self._draft = {"mnemonic": mn, "passphrase": passphrase or "", "name": name.strip()}
        quiz = sorted(secrets.SystemRandom().sample(range(24), 3))
        self._draft["quiz"] = quiz
        return {"words": mn.split(), "quiz": quiz}

    def m_check_quiz(self, index, word):
        if not self._draft:
            raise ApiError("Start again — no wallet is being created.", "no_draft")
        return {"ok": self._draft["mnemonic"].split()[int(index)] == (word or "").strip().lower()}

    def m_import_wallet(self, words, passphrase="", name=""):
        mn = " ".join((words or "").lower().replace(",", " ").split())
        n = len(mn.split())
        if n not in (12, 15, 18, 21, 24):
            raise ApiError("A seed phrase has 12, 15, 18, 21 or 24 words.", "bad_seed")
        if HAS_BTC:
            valid = btcv.bip39.mnemonic_is_valid(mn)
        else:
            from eth_account.hdaccount import Mnemonic
            valid = Mnemonic("english").is_mnemonic_valid(mn)
        if not valid:
            raise ApiError("Invalid seed phrase (unknown word or bad checksum).", "bad_seed")
        self._draft = {"mnemonic": mn, "passphrase": passphrase or "", "name": name.strip(), "quiz": []}
        return {"words": n}

    def m_commit_draft(self, pin=None):
        """First wallet: creates the encrypted vault with `pin`.  Later wallets: vault must already be unlocked."""
        d = self._draft
        if not d:
            raise ApiError("Nothing to save — start again.", "no_draft")
        if not self.store.initialized():
            p = weak_pin(pin or "")
            if p:
                raise ApiError(p, "weak_pin")
            self.store.init(pin)
        elif not self.store.unlocked:
            raise vs.Locked("Vault is locked.")
        info = self._derive_info(d["mnemonic"], d["passphrase"])
        for w in self.store.list_wallets():
            if w.get("fp") == info["fp"]:
                raise ApiError(f"This seed is already in the vault as “{w['name']}”.", "duplicate")
        n = len(self.store.list_wallets())
        name = d["name"] or ("Main Account" if n == 0 else f"Account {n + 1}")
        wid = self.store.add_wallet({"name": name, "color": COLORS[n % len(COLORS)], "fp": info["fp"]},
                                    {"mnemonic": d["mnemonic"], "passphrase": d["passphrase"]})
        self._draft = None
        self._last = time.monotonic()
        st = self._state()
        st["new_wid"] = wid
        return st

    def m_cancel_draft(self):
        self._draft = None
        return {}

    def m_set_btc_type(self, wid, index):
        """Bitcoin address type for one account (index into BTC_TYPES). Stored encrypted in the wallet record."""
        index = int(index)
        if index not in range(len(BTC_TYPES)):
            raise ApiError("Unknown address type.", "bad_type")
        self.store.update_meta(int(wid), btc_type=index)
        return self._state()

    def m_get_phrase(self, pin, wid):
        self.store.verify_pin(pin)
        mn, pp = self._secret(int(wid))
        return {"words": mn.split(), "passphrase": bool(pp)}

    # ---------------- scanning ----------------
    def m_scan_reset(self):
        self._collector = Collector()
        return {}

    def m_scan_feed(self, text):
        try:
            done, prog = self._collector.feed(text)
        except Exception as e:
            return {"done": False, "error": str(e)}
        if done is not None:
            return {"done": True, "text": done}
        return {"done": False, "progress": list(prog)}

    # ---------------- review + sign ----------------
    def m_review(self, text, wid, net="btc", allow_unsafe=False):
        wid = int(wid)
        chain = detect_request(text)
        if chain == ETH:
            if not HAS_ETH:
                raise ApiError(f"Ethereum engine unavailable: {ETH_ERR}", "no_engine")
            return self._review_eth(text, wid)
        if not HAS_BTC:
            raise ApiError(f"Bitcoin engine unavailable: {BTC_ERR}", "no_engine")
        return self._review_btc(text, wid, net, bool(allow_unsafe))

    def _review_eth(self, text, wid):
        rq, tx, review, known = core.review_request(text)
        cid = tx["chainId"]
        sym, net = core.sym_for(cid), core.net_of(cid)
        mine = self._info(wid)["eth"]
        warns, errs = [], []
        want = ("0x" + bytes(rq["address"]).hex()) if rq.get("address") else None
        if want and want.lower() != mine.lower():
            errs.append(f"This request is for {want}, but the selected account is {mine}. Switch account.")
        if not net:
            warns.append(f"Unknown network (chainId {cid}). Check it carefully.")
        data = tx.get("data", "0x")
        calls = core.describe_calldata(cid, tx["to"], data) if data not in ("0x", "") else ""
        if "UNLIMITED" in calls:
            warns.append("This approves an UNLIMITED token allowance.")
        if "unrecognised" in calls or "UNKNOWN token" in calls:
            warns.append("The contract call could not be fully decoded. Verify it on a block explorer.")
        if tx["to"] is None:
            warns.append("This creates a new contract.")
        price = tx["gasPrice"] if tx.get("type") == 0 else tx["maxFeePerGas"]
        rows = [{"k": "Network", "v": f"{net or 'Unknown'} (chain {cid})"},
                {"k": "Type", "v": "Contract creation" if tx["to"] is None else
                 ("Contract call" if data not in ("0x", "") else "Send")},
                {"k": "From", "v": want or mine, "mono": True, "long": True},
                {"k": "To", "v": tx["to"] or "(new contract)", "mono": True, "long": True},
                {"k": "Amount", "v": f"{core.to_eth(tx['value'])} {sym}", "mono": True, "strong": True},
                {"k": "Max network fee", "v": f"{core.to_eth(tx['gas'] * price)} {sym}", "mono": True},
                {"k": "Max total", "v": f"{core.to_eth(tx['value'] + tx['gas'] * price)} {sym}", "mono": True,
                 "accent": True}]
        self._pending = {"chain": ETH, "wid": wid, "rq": rq, "tx": tx, "summary": f"{core.to_eth(tx['value'])} {sym}",
                         "to": tx["to"], "net": "bnb" if cid == 56 else "eth", "label": net or f"chain {cid}",
                         "real": core.is_real(cid)}
        return {"chain": ETH, "title": "Ethereum / EVM", "net_key": self._pending["net"], "network": net or f"chain {cid}",
                "real": core.is_real(cid), "rows": rows, "calls": calls, "warnings": warns, "errors": errs,
                "can_sign": not errs, "unsafe_hint": False, "detail": review}

    @staticmethod
    def _guess_script(psbt, default=None):
        for inp in psbt.inputs:
            try:
                u = inp.utxo
                if u is not None:
                    s = _SPK_TO_SCRIPT.get(u.script_pubkey.script_type())
                    if s:
                        return s
            except Exception:
                pass
        return default or btcv.DEFAULT_SCRIPT

    def _review_btc(self, text, wid, net_key, unsafe):
        network = NETS.get(net_key, (BTC, None))[1] or "Bitcoin Mainnet"       # unknown/EVM selection -> strictest
        psbt = btcv.psbt_from_text(text)
        meta = next((w for w in self.store.list_wallets() if w["id"] == wid), {})
        ty = meta.get("btc_type", 0)
        script = self._guess_script(psbt, BTC_TYPES[ty if ty in range(len(BTC_TYPES)) else 0][1])
        mn, pp = self._secret(wid)
        w = btcv.Wallet(mn, pp, network, script=script)
        rv = btcv.analyze_psbt(psbt, w.watch, unsafe)
        real = not btcv.NETWORKS[network]["test"]
        rows = [{"k": "Network", "v": network + ("" if real else "  (test coins)")},
                {"k": "Address type", "v": btcv.script_label(script)}]
        sends = [o for o in rv["outputs"] if o["kind"] == "external"]
        for o in sends:
            rows.append({"k": "Send to", "v": o["address"], "mono": True, "long": True})
            rows.append({"k": "Amount", "v": btcv.to_btc(o["value"]) + " BTC", "mono": True, "strong": True})
        for o in rv["outputs"]:
            if o["kind"] in ("change", "self"):
                rows.append({"k": "Change (yours)" if o["kind"] == "change" else "To yourself",
                             "v": btcv.to_btc(o["value"]) + " BTC", "mono": True})
            elif o["kind"] == "opreturn":
                rows.append({"k": "OP_RETURN", "v": "data output", "mono": True})
        if rv["fee"] is not None and rv["fee"] >= 0:
            rows.append({"k": "Network fee", "v": f"{btcv.to_btc(rv['fee'])} BTC  (~{rv['feerate']:.1f} sat/vB)",
                         "mono": True})
            rows.append({"k": "Total leaving wallet", "v": btcv.to_btc(rv["external_total"] + rv["fee"]) + " BTC",
                         "mono": True, "accent": True})
        rows.append({"k": "Inputs", "v": f"{len(rv['inputs'])} ({sum(1 for i in rv['inputs'] if i['mine'])} yours)"})
        rows.append({"k": "Txid", "v": rv["txid"], "mono": True, "long": True})
        errs = list(rv["errors"])
        if not any(i["mine"] for i in rv["inputs"]) and not errs:
            errs.append("None of the inputs belong to the selected account (or address type). Switch account.")
        total = sum(o["value"] for o in sends)
        self._pending = {"chain": BTC, "wid": wid, "psbt": psbt, "network": network, "script": script, "unsafe": unsafe,
                         "summary": f"{btcv.to_btc(total)} BTC", "to": sends[0]["address"] if sends else None,
                         "net": net_key if NETS.get(net_key, (None,))[0] == BTC else "btc",
                         "label": network, "real": real}
        return {"chain": BTC, "title": "Bitcoin", "net_key": self._pending["net"], "network": network, "real": real,
                "rows": rows, "calls": "", "warnings": list(rv["warnings"]), "errors": errs, "can_sign": not errs,
                "unsafe_hint": any("previous transaction missing" in e for e in errs), "detail": btcv.format_review(rv)}

    def m_sign(self, pin):
        p = self._pending
        if not p:
            raise ApiError("Nothing to sign — scan the request again.", "no_pending")
        self.store.verify_pin(pin)                         # counts attempts; raises BadPin / Wiped
        mn, pp = self._secret(p["wid"])
        if p["chain"] == ETH:
            from eth_account import Account
            key = Account.from_mnemonic(mn, passphrase=pp).key
            sig, addr = evur.sign_request_with_key(p["rq"], p["tx"], key)
            frames = evur.ur_encode_frames("eth-signature", evur.signature_cbor(p["rq"]["request_id"], sig), 100)
            res = {"chain": ETH, "frames": frames, "signer": addr, "complete": True,
                   "note": "Show this QR to the wallet app — it broadcasts the transaction.",
                   "copy": "\n".join(f.lower() for f in frames), "file_name": "eth-signature.txt",
                   "file": "\n".join(f.lower() for f in frames)}
        else:
            hw = self.store.settings().get("btc_hw_mode", True)
            w = btcv.Wallet(mn, pp, p["network"], script=p["script"])
            r = btcv.sign_psbt(p["psbt"], w, p["unsafe"], finalize=not hw)
            frames = btcv.psbt_ur_frames(r["psbt"], 100)
            note = ("Scan this QR back into the wallet that made the request — it finalises and broadcasts."
                    if hw else "Finalised — ready to broadcast." if r["complete"] else
                    "PARTIAL — other inputs need their own signer.")
            res = {"chain": BTC, "frames": frames, "complete": r["complete"], "txid": r["txid"], "note": note,
                   "copy": r["psbt"].to_base64(), "file_name": "signed.psbt", "file": r["psbt"].serialize()}
        self.store.add_history(p["wid"], {"kind": "signed", "chain": p["chain"], "net": p["net"], "label": p["label"],
                                          "amount": p["summary"], "to": p["to"], "real": p["real"],
                                          "txid": res.get("txid")})
        self._signed = {"name": res["file_name"], "data": res.pop("file")}
        self._pending = None
        res["svgs"] = [qr_svg(f) for f in frames]
        res["frames"] = frames
        return res

    def m_cancel_review(self):
        self._pending = None
        return {}

    def m_save_signed(self):
        if not self._signed:
            raise ApiError("Nothing signed yet.", "no_signed")
        if not (self.host and hasattr(self.host, "save_file")):
            raise ApiError("This host has no file dialog — use Copy instead.", "no_host")
        path = self.host.save_file(self._signed["name"], self._signed["data"])
        return {"path": path}

    # ---------------- receive / pair / export ----------------
    def m_qr(self, text):
        return {"svg": qr_svg(text)}

    def _public_json(self, wid, btc_net):
        mn, pp = self._secret(wid)
        out = {"vault_pub": 1, "fingerprint": self._info(wid)["fp"], "accounts": {}}
        if HAS_BTC:
            for sc in btcv.SCRIPTS:
                w = btcv.Wallet(mn, pp, btc_net, script=sc)
                out["accounts"][sc] = {"network": btc_net, "path": w.path, "xpub": w.watch.slip132(),
                                       "origin": w.watch.key_origin(), "first_address": w.watch.address(0, 0)}
        if HAS_ETH:
            x = evur.derive_account_xpub(mn, pp)
            out["accounts"]["evm"] = {"path": "m/44'/60'/0'", "account_pub": x["pub"].hex(),
                                      "chain_code": x["chain"].hex(), "first_address": self._info(wid)["eth"]}
        return json.dumps(out, separators=(",", ":"))

    def m_export_pub(self, wid, btc_net="btc"):
        wid = int(wid)
        btc_name = NETS.get(btc_net, (None, "Bitcoin Mainnet"))[1] or "Bitcoin Mainnet"
        text = self._public_json(wid, btc_name)
        frames = evf_frames(text, 400)
        return {"frames": frames, "svgs": [qr_svg(f) for f in frames], "text": text, "file_name": "vault-public-keys.json"}

    # app id -> (BTC kind, ETH PAIR_CHOICES index)
    _PAIR = {"kn": ("multi", 0), "ok": ("multi", 1), "mm": (None, 2), "rb": (None, 3), "us": ("account", None)}

    def m_pair(self, app, wid, nets, btc_net="btc"):
        wid = int(wid)
        mn, pp = self._secret(wid)
        nets = set(nets or [])
        want_btc, want_eth = bool(nets & {"btc"}), bool(nets & {"eth", "bnb"})
        notes = []
        if app in ("vw", "ot"):
            return self.m_export_pub(wid, btc_net) | {"notes": ["Vault public-key export (JSON). No secrets inside."]}
        if app not in self._PAIR:
            raise ApiError("Unknown app.", "bad_app")
        kind, eth_idx = self._PAIR[app]
        if want_btc and kind and HAS_BTC:
            name = NETS.get(btc_net, (None, "Bitcoin Mainnet"))[1] or "Bitcoin Mainnet"
            w = btcv.Wallet(mn, pp, name)
            if kind == "multi" and btcv.NETWORKS[name]["test"]:
                notes.append("OKX / Keystone import is built for mainnet and may reject a test-network QR.")
            frames = btcv.keystone_frames(btcv.keystone_bundle(w), kind, 160 if kind == "multi" else 120)
            notes.append("Bitcoin: Native SegWit (BIP-84) account." if kind == "account" else
                         "One scan carries the Bitcoin and EVM accounts.")
        elif want_eth and eth_idx is not None and HAS_ETH:
            frames, addr, xfp = core.pairing_frames(mn, pp, eth_idx)
            notes.append(f"First account {addr} — compare it with the address shown here before pairing.")
        else:
            raise ApiError("Select at least one network this app supports.", "no_nets")
        return {"frames": frames, "svgs": [qr_svg(f) for f in frames], "notes": notes}

    # ---------------- sync / history ----------------
    def m_import_sync(self, text, wid):
        """Placeholder 'vault-sync/1' JSON until the Vault Watch companion defines the real format:
        {"v":1,"fp":"<master fp hex, optional>","balances":{"btc":{"amt":0.1,"usd":6400},"eth":{...}},
         "history":[{"ts":1760000000,"net":"btc","dir":"in","amt":"0.05 BTC"}]}"""
        try:
            d = json.loads(text)
        except Exception:
            raise ApiError("Not a sync file (expected JSON).", "bad_sync")
        if not isinstance(d, dict) or d.get("v") != 1 or not isinstance(d.get("balances", {}), dict):
            raise ApiError("Unsupported sync format.", "bad_sync")
        wid = int(wid)
        if d.get("fp"):
            m = next((w for w in self.store.list_wallets() if w.get("fp") == d["fp"]), None)
            if not m:
                raise ApiError("This sync file is for a different wallet.", "bad_sync")
            wid = m["id"]
        bal = {}
        for k, v in d.get("balances", {}).items():
            if k in NETS and isinstance(v, dict):
                bal[k] = {"amt": float(v.get("amt", 0)), "usd": float(v.get("usd", 0))}
        hist = [{"ts": int(h.get("ts", 0)), "net": str(h.get("net", "")), "dir": "out" if h.get("dir") == "out" else "in",
                 "amt": str(h.get("amt", ""))[:40]} for h in d.get("history", [])[:200] if isinstance(h, dict)]
        self.store.set_sync(wid, {"updated": time.time(), "balances": bal, "history": hist})
        st = self._state()
        st["synced_wid"] = wid
        return st

    def m_history(self, wid):
        wid = int(wid)
        items = []
        for h in self.store.list_history(wid, 100):
            items.append({"ts": h["ts"], "dir": "signed", "title": f"Signed {h.get('chain', '')} transaction",
                          "amt": h.get("amount", ""), "sub": (h.get("label") or "") + (" · REAL FUNDS" if h.get("real") else "")})
        s = self.store.get_sync(wid)
        for h in (s or {}).get("history", []):
            items.append({"ts": h["ts"], "dir": h["dir"], "title": ("Received " if h["dir"] == "in" else "Sent ") + h["net"].upper(),
                          "amt": h["amt"], "sub": "from sync"})
        items.sort(key=lambda x: -x["ts"])
        return {"items": items}
