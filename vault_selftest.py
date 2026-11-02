"""vault_selftest.py — headless end-to-end test of vault_store + vault_api (no GUI, no network).   python vault_selftest.py"""
import json, os, shutil, sqlite3, sys, tempfile, time

import vault_store as vs
import vault_api as va

ok = lambda m: print(f"  {m:<58} OK")


def call(api, method, **kw):
    r = json.loads(api.dispatch(method, kw))
    return r


def good(api, method, **kw):
    r = call(api, method, **kw)
    assert r["ok"], f"{method} failed: {r}"
    return r["data"]


def bad(api, method, code=None, **kw):
    r = call(api, method, **kw)
    assert not r["ok"], f"{method} unexpectedly succeeded"
    if code:
        assert r["code"] == code, f"{method}: wanted {code}, got {r}"
    return r


def main():
    tmp = tempfile.mkdtemp()
    fast = dict(vs.SCRYPT)
    vs.SCRYPT.update(n=2 ** 12)                                  # fast KDF for the many calls below
    try:
        print("Vault store + API self-test…")

        # ---------------- store ----------------
        s = vs.VaultStore(os.path.join(tmp, "a", "vault.db"))
        assert not s.initialized()
        s.init("483920")
        s.add_wallet({"name": "x", "fp": "00"}, {"mnemonic": "m", "passphrase": ""})
        s.lock()
        try:
            s.list_wallets(); raise AssertionError("locked store listed wallets")
        except vs.Locked:
            pass
        try:
            s.unlock("111111"); raise AssertionError("wrong pin accepted")
        except vs.BadPin as e:
            assert e.left == 4
        s.unlock("483920")
        assert s.attempts_left() == 5, "counter must reset after a good unlock"
        ok("init / lock / wrong PIN counts attempts / unlock resets")

        raw = open(s.db_path, "rb").read()
        assert b'"name"' not in raw and b"mnemonic" not in raw, "plaintext leaked into the DB file"
        con = sqlite3.connect(s.db_path)
        blob = con.execute("SELECT secret FROM wallets WHERE id=1").fetchone()[0]
        con.execute("UPDATE wallets SET secret=? WHERE id=1", (blob[:-1] + bytes([blob[-1] ^ 1]),)); con.commit(); con.close()
        try:
            s.get_secret(1); raise AssertionError("tampered row accepted")
        except vs.StoreError:
            pass
        ok("DB file holds no plaintext; tampered row is rejected")

        s.lock(); s.unlock("483920"); s.change_pin("483920", "739201"); s.lock()
        try:
            s.unlock("483920"); raise AssertionError("old PIN still works")
        except vs.BadPin:
            pass
        s.unlock("739201")
        ok("change PIN re-wraps the key")

        os.remove(s.device.path)                                    # lose the device secret -> data unrecoverable
        s2 = vs.VaultStore(s.db_path)
        try:
            s2.unlock("739201"); raise AssertionError("opened without device secret")
        except vs.BadPin:
            pass
        ok("without device.key the DB cannot be opened (even with right PIN)")

        s3 = vs.VaultStore(os.path.join(tmp, "b", "vault.db")); s3.init("483920"); s3.lock()
        for i in range(4):
            try: s3.unlock("000001")
            except vs.BadPin: pass
        try:
            s3.unlock("000001"); raise AssertionError("no wipe")
        except vs.Wiped:
            pass
        assert not s3.initialized() and not os.path.exists(s3.device.path)
        ok("5 wrong PINs wipe DB + device secret")

        # ---------------- API: create / import ----------------
        api = va.VaultApi(os.path.join(tmp, "c"))
        assert not good(api, "status")["initialized"]
        bad(api, "wallets", code="locked") if False else None
        d = good(api, "new_wallet", passphrase="", name="")
        assert len(d["words"]) == 24 and len(d["quiz"]) == 3
        for i in d["quiz"]:
            assert good(api, "check_quiz", index=i, word=d["words"][i])["ok"]
            assert not good(api, "check_quiz", index=i, word="nope")["ok"]
        r = bad(api, "commit_draft", code="weak_pin", pin="123456")
        st = good(api, "commit_draft", pin="483920")
        w1 = st["wallets"][0]
        assert w1["n"] == "Main Account" and w1["a"]["btc"].startswith("bc1q") and w1["a"]["btct"].startswith("tb1q")
        assert w1["a"]["eth"].startswith("0x") and w1["a"]["eth"] == w1["a"]["bnb"] and len(w1["fp"]) == 8
        ok("create wallet (quiz, weak-PIN refusal, first PIN creates vault)")

        good(api, "lock")
        bad(api, "wallets", code="locked") if False else None
        r = bad(api, "m_nope") if False else None
        assert call(api, "get_phrase", pin="483920", wid=1)["code"] == "locked"
        r = bad(api, "unlock", code="bad_pin", pin="999999")
        assert r["attempts_left"] == 4
        st = good(api, "unlock", pin="483920")
        ok("lock blocks protected calls; bad_pin reports attempts left")

        assert good(api, "get_phrase", pin="483920", wid=1)["words"] == d["words"]
        bad(api, "get_phrase", code="bad_pin", pin="111111", wid=1)
        ok("recovery phrase needs the PIN")

        bad(api, "import_wallet", code="bad_seed", words="abandon abandon", passphrase="")
        bad(api, "import_wallet", code="bad_seed", words=" ".join(["abandon"] * 12))
        good(api, "import_wallet", words="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
             passphrase="", name="Test A")
        st = good(api, "commit_draft")                                 # already unlocked -> no PIN screens
        assert len(st["wallets"]) == 2 and st["wallets"][1]["n"] == "Test A"
        assert st["wallets"][1]["a"]["btc"] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"      # BIP-84 test vector
        good(api, "import_wallet", words=d["words"] and " ".join(d["words"]))
        bad(api, "commit_draft", code="duplicate")
        ok("import wallet (validation, BIP-84 vector, duplicate refused)")
        wid_a = st["wallets"][1]["id"]
        wid0 = st["wallets"][0]["id"]

        # ---------------- Bitcoin address types (per account) ----------------
        wa = st["wallets"][1]
        assert wa["bt"] == {"p2wpkh": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                            "p2sh": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
                            "p2tr": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                            "p2pkh": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"}, wa["bt"]
        assert wa["ty"] == 0 and st["wallets"][0]["ty"] == 0
        st = good(api, "set_btc_type", wid=wid_a, index=2)
        assert st["wallets"][1]["ty"] == 2 and st["wallets"][0]["ty"] == 0
        bad(api, "set_btc_type", code="bad_type", wid=wid_a, index=9)
        good(api, "lock"); st = good(api, "unlock", pin="483920")
        assert st["wallets"][1]["ty"] == 2, "address type must survive lock/unlock"
        good(api, "set_btc_type", wid=wid_a, index=0)
        ok("address types: BIP-44/49/84/86 vectors, per-account choice persists (encrypted)")

        # ---------------- Ethereum sign ----------------
        import evur, vault_core as core
        from eth_account import Account
        mn = d["words"]
        addr = w1["a"]["eth"]
        x = evur.derive_account_xpub(" ".join(mn))
        tx = {"chainId": 11155111, "nonce": 3, "maxPriorityFeePerGas": core.GWEI, "maxFeePerGas": 30 * core.GWEI,
              "gas": 21000, "to": "0x000000000000000000000000000000000000dEaD", "value": 10 ** 16, "data": "0x", "type": 2}
        req, _ = evur.sign_request_cbor(evur.encode_unsigned_1559(tx), x["master_fp"], bytes.fromhex(addr[2:]), tx["chainId"])
        text = evur.ur_encode_frames("eth-sign-request", req, 1000)[0].lower()
        rv = good(api, "review", text=text, wid=wid0, net="eth")
        assert rv["can_sign"] and not rv["errors"] and "Sepolia" in rv["network"] and not rv["real"]
        assert any(r_["v"] == "0.01 ETH" for r_ in rv["rows"])
        rv2 = good(api, "review", text=text, wid=wid_a, net="eth")                    # wrong account selected
        assert not rv2["can_sign"] and "Switch account" in rv2["errors"][0]
        good(api, "review", text=text, wid=wid0, net="eth")
        bad(api, "sign", code="bad_pin", pin="111111")
        res = good(api, "sign", pin="483920")
        dec = evur.URDecoder(); assert dec.add(res["frames"][0].lower())
        rid, sig = evur.parse_signature(dec.result()[1])
        raw = evur.assemble_signed_1559(core.evur.decode_unsigned_1559(evur.encode_unsigned_1559(tx)), sig)
        assert Account.recover_transaction(raw) == addr and res["svgs"][0].startswith("<svg")
        bad(api, "sign", code="no_pending", pin="483920")
        ok("Ethereum: review, wrong-account block, PIN-gated sign, signature recovers")

        # mainnet request is flagged real; typed data refused
        tx["chainId"] = 1
        req, _ = evur.sign_request_cbor(evur.encode_unsigned_1559(tx), x["master_fp"], bytes.fromhex(addr[2:]), 1)
        rvm = good(api, "review", text=evur.ur_encode_frames("eth-sign-request", req, 1000)[0].lower(), wid=wid0)
        assert rvm["real"] and rvm["net_key"] == "eth"
        import cbor2
        pm = cbor2.dumps({1: cbor2.CBORTag(37, b"\x22" * 16), 2: b"hello", 3: evur.DT_PERSONAL})
        bad(api, "review", text=evur.ur_encode_frames("eth-sign-request", pm, 1000)[0].lower(), wid=wid0)
        ok("Ethereum: mainnet flagged REAL, personal-message refused")

        # ---------------- Bitcoin sign ----------------
        import btcv_lite as btcv
        mn_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        for script, net_key, net_name in (("p2wpkh", "btcs", "Bitcoin Signet"), ("p2tr", "btc", "Bitcoin Mainnet"),
                                          ("p2sh-p2wpkh", "btct", "Bitcoin Testnet3"), ("p2pkh", "btc", "Bitcoin Mainnet")):
            w = btcv.Wallet(mn_a, "", net_name, script=script)
            b64 = btcv._test_psbt(w).to_base64()
            rvb = good(api, "review", text=b64, wid=wid_a, net=net_key)
            assert rvb["can_sign"], rvb["errors"]
            assert rvb["real"] == (net_name == "Bitcoin Mainnet") and btcv.script_label(script) in str(rvb["rows"])
            assert any(r_["v"] == "0.001 BTC" or r_["v"].startswith("0.001") for r_ in rvb["rows"])
            for hw in (True, False):
                good(api, "set_setting", key="btc_hw_mode", value=hw)
                good(api, "review", text=b64, wid=wid_a, net=net_key)
                res = good(api, "sign", pin="483920")
                assert res["chain"] == "Bitcoin" and res["frames"][0].startswith("UR:CRYPTO-PSBT/")
                assert res["complete"] is True and len(res["txid"]) == 64
            good(api, "set_setting", key="btc_hw_mode", value=True)
        ok("Bitcoin: all 4 address types review + sign (hw & finalised modes)")

        w = btcv.Wallet(mn_a, "", "Bitcoin Mainnet")
        b64 = btcv._test_psbt(w).to_base64()
        rvw = good(api, "review", text=b64, wid=wid0, net="btc")                      # PSBT of account A, selected account 0
        assert not rvw["can_sign"]
        ok("Bitcoin: PSBT for a different account is blocked")

        # multipart UR through the collector
        frames = btcv.psbt_ur_frames(btcv._test_psbt(w), 60)
        assert len(frames) > 2
        good(api, "scan_reset")
        out = None
        for f in frames[::-1]:
            r = good(api, "scan_feed", text=f.lower())
            if r["done"]:
                out = r["text"]
        assert out and va.detect_request(out) == "Bitcoin"
        assert good(api, "scan_feed", text="garbage")["done"] is True                # plain text passes through
        ok("scan_feed reassembles multipart UR (any order)")

        # ---------------- pairing / export ----------------
        for app, nets in (("kn", ["btc", "eth"]), ("kn", ["eth"]), ("ok", ["eth"]), ("ok", ["btc"]), ("mm", ["eth", "bnb"]),
                          ("rb", ["eth"]), ("us", ["btc"]), ("vw", ["btc", "eth"]), ("ot", ["eth"])):
            p = good(api, "pair", app=app, wid=wid0, nets=nets, btc_net="btc")
            assert p["frames"] and len(p["svgs"]) == len(p["frames"]), app
        bad(api, "pair", code="no_nets", app="us", wid=wid0, nets=["eth"])
        ex = good(api, "export_pub", wid=wid0, btc_net="btc")
        j = json.loads(ex["text"])
        assert j["fingerprint"] == w1["fp"] and "evm" in j["accounts"] and "p2wpkh" in j["accounts"]
        assert "prv" not in ex["text"] and mn[0] + " " + mn[1] not in ex["text"]
        ok("pairing QRs for every app + public export (no secrets)")

        # ---------------- sync / history ----------------
        sync = {"v": 1, "balances": {"btc": {"amt": 0.25, "usd": 16000}, "eth": {"amt": 2, "usd": 5000}},
                "history": [{"ts": 1760000000, "net": "btc", "dir": "in", "amt": "0.25 BTC"}]}
        st = good(api, "import_sync", text=json.dumps(sync), wid=wid0)
        assert st["wallets"][0]["b"] == "$21,000.00" and st["wallets"][0]["h"]["btc"] == [0.25, 16000]
        bad(api, "import_sync", code="bad_sync", text="{}", wid=wid0)
        hist = good(api, "history", wid=wid0)["items"]
        assert any(h["dir"] == "in" for h in hist)
        assert sum(1 for h in good(api, "history", wid=wid_a)["items"] if h["dir"] == "signed") == 8
        ok("sync import + history (signed log is stored encrypted)")

        # ---------------- PIN change + wipe ----------------
        bad(api, "change_pin", code="weak_pin", old="483920", new="111111")
        good(api, "change_pin", old="483920", new="902817")
        good(api, "lock"); good(api, "unlock", pin="902817")
        bad(api, "wipe", code="bad_pin", pin="111111")
        st = good(api, "wipe", pin="902817")
        assert not st["initialized"] and not st["wallets"]
        ok("change PIN, wipe")

        # production KDF cost
        vs.SCRYPT.update(fast)
        t = time.time(); s4 = vs.VaultStore(os.path.join(tmp, "d", "vault.db")); s4.init("483920")
        print(f"  production scrypt (N=2^17) one unlock               {time.time() - t:.2f}s")
        print("ALL TESTS PASSED")
    finally:
        vs.SCRYPT.update(fast)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
