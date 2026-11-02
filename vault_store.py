"""
vault_store.py — PIN-protected, encrypted wallet database for Vault Signer.  NO GUI, NO network.

Layout (SQLite, stdlib only):
    meta    k/v        KDF params, wrapped data key, failed-PIN counter, plain settings (no secrets)
    wallets id         meta  = AES-GCM(name, colour, fingerprint ...)
                       secret= AES-GCM(mnemonic, bip39 passphrase)        <- the keys
    sync    wid        AES-GCM(imported balances)
    history id         AES-GCM(signing log entry)

Key hierarchy
    PIN --scrypt--> pin_key  --HKDF(salt = device secret)-->  KEK  --AES-GCM unwrap-->  MK (random 32 bytes)
    MK encrypts every row (AES-256-GCM, AAD = "table:id:field", so rows can't be swapped around).
    Changing the PIN only re-wraps MK; wiping deletes the DB *and* the device secret (crypto-erase).

Device secret
    Desktop/testing : a random 32-byte file (device.key) next to the DB (or VAULT_DEVICE_KEY=path, e.g. on a USB stick).
    Android         : pass your own provider whose get() returns a key that lives in the Android Keystore
                      (hardware-backed, non-exportable).  THAT is what makes a 6-digit PIN safe: without it an attacker
                      holding a copy of the files can try all 10^6 PINs offline (scrypt only slows each try).
                      The failed-attempt counter below only protects against someone using the app itself.

Needs: pycryptodome (or cryptography).  scrypt: hashlib.scrypt, falling back to pycryptodome.
"""
import hashlib, hmac, json, os, sqlite3, time, unicodedata

try:                                                     # AES-256-GCM backend
    from Crypto.Cipher import AES as _AES

    def _enc(key, nonce, pt, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(pt)
        return ct + tag

    def _dec(key, nonce, blob, aad):
        c = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        return c.decrypt_and_verify(blob[:-16], blob[-16:])        # ValueError on wrong key / tampering
except ImportError:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

    def _enc(key, nonce, pt, aad):
        return _AESGCM(key).encrypt(nonce, pt, aad)

    def _dec(key, nonce, blob, aad):
        try:
            return _AESGCM(key).decrypt(nonce, blob, aad)
        except Exception:
            raise ValueError("MAC check failed")

SCRYPT = {"n": 2 ** 17, "r": 8, "p": 1}
DEFAULT_SETTINGS = {"autolock": 60, "max_attempts": 5, "btc_hw_mode": True}   # autolock seconds (0 = never); attempts 0 = never wipe


class StoreError(Exception):
    pass


class BadPin(StoreError):
    def __init__(self, left):
        super().__init__(f"Wrong PIN. {left} attempt{'s' if left != 1 else ''} left." if left is not None
                         else "Wrong PIN.")
        self.left = left


class Wiped(StoreError):
    pass


class Locked(StoreError):
    pass


# ------------------------------- helpers ------------------------------------
def _scrypt(secret: bytes, salt: bytes, n, r, p) -> bytes:
    if not (2 ** 12 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise StoreError("Unreasonable scrypt parameters in database; refusing to open it.")
    try:
        return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2 ** 30)
    except (AttributeError, ValueError):
        from Crypto.Protocol.KDF import scrypt
        return scrypt(secret, salt, 32, N=n, r=r, p=p)


def _hkdf(ikm: bytes, salt: bytes, info: bytes, n=32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    for i in range(1, -(-n // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:n]


def _pin_bytes(pin: str) -> bytes:
    return unicodedata.normalize("NFKC", pin).encode()


class FileDeviceSecret:
    """32 random bytes in a file (created on first use). Replace with an Android-Keystore-backed provider on phones."""

    def __init__(self, path):
        self.path = path

    def get(self) -> bytes:
        if os.path.exists(self.path):
            b = open(self.path, "rb").read()
            if len(b) != 32:
                raise StoreError("device.key is damaged — without it the database cannot be opened.")
            return b
        b = os.urandom(32)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        return b

    def destroy(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r+b") as f:
                    f.write(b"\x00" * 32); f.flush(); os.fsync(f.fileno())
                os.remove(self.path)
        except OSError:
            pass


# --------------------------------- store ------------------------------------
class VaultStore:
    def __init__(self, db_path, device=None):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.device = device or FileDeviceSecret(
            os.environ.get("VAULT_DEVICE_KEY") or os.path.join(os.path.dirname(os.path.abspath(db_path)), "device.key"))
        self._mk = None                                   # bytearray while unlocked

    # ---- sqlite plumbing ----
    def _db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA secure_delete=ON")
        con.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB);
            CREATE TABLE IF NOT EXISTS wallets(id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER, meta BLOB, secret BLOB);
            CREATE TABLE IF NOT EXISTS sync(wid INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, wid INTEGER, ts INTEGER, data BLOB);
        """)
        return con

    def _get(self, con, k, default=None):
        r = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def _put(self, con, k, v):
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))

    def initialized(self) -> bool:
        if not os.path.exists(self.db_path):
            return False
        con = self._db()
        try:
            return self._get(con, "wrapped_mk") is not None
        finally:
            con.close()

    @property
    def unlocked(self) -> bool:
        return self._mk is not None

    # ---- row encryption ----
    def _seal(self, table, rid, field, obj) -> bytes:
        if self._mk is None:
            raise Locked("Vault is locked.")
        nonce = os.urandom(12)
        aad = f"{table}:{rid}:{field}".encode()
        return nonce + _enc(bytes(self._mk), nonce, json.dumps(obj, separators=(",", ":")).encode(), aad)

    def _open(self, table, rid, field, blob):
        if self._mk is None:
            raise Locked("Vault is locked.")
        try:
            return json.loads(_dec(bytes(self._mk), blob[:12], blob[12:], f"{table}:{rid}:{field}".encode()))
        except ValueError:
            raise StoreError(f"Database row {table}:{rid} failed its integrity check (tampered or corrupted).")

    # ---- PIN / key wrapping ----
    def _kek(self, pin, salt, kdf):
        pk = _scrypt(_pin_bytes(pin), salt, kdf["n"], kdf["r"], kdf["p"])
        return _hkdf(pk, self.device.get(), b"vault-kek-v1")

    def init(self, pin: str):
        if self.initialized():
            raise StoreError("Vault already initialised.")
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        mk, salt, nonce = os.urandom(32), os.urandom(16), os.urandom(12)
        kek = self._kek(pin, salt, SCRYPT)
        con = self._db()
        try:
            self._put(con, "kdf", json.dumps({**SCRYPT, "salt": salt.hex()}).encode())
            self._put(con, "wrapped_mk", nonce + _enc(kek, nonce, mk, b"vault:wrapped_mk"))
            self._put(con, "fails", b"0")
            self._put(con, "settings", json.dumps(DEFAULT_SETTINGS).encode())
            con.commit()
        finally:
            con.close()
        self._mk = bytearray(mk)

    def _unwrap(self, pin):
        con = self._db()
        try:
            kdf = json.loads(self._get(con, "kdf"))
            wrapped = self._get(con, "wrapped_mk")
        finally:
            con.close()
        kek = self._kek(pin, bytes.fromhex(kdf["salt"]), kdf)
        return _dec(kek, wrapped[:12], wrapped[12:], b"vault:wrapped_mk")

    def _check(self, pin: str):
        """Count the attempt FIRST (so pulling the plug mid-try doesn't give a free guess), then verify.
        Returns the master key. Raises BadPin / Wiped."""
        if not self.initialized():
            raise StoreError("No vault on this device yet.")
        con = self._db()
        try:
            fails = int(self._get(con, "fails", b"0")) + 1
            limit = self.settings().get("max_attempts", 5)
            self._put(con, "fails", str(fails).encode())
            con.commit()
        finally:
            con.close()
        try:
            mk = self._unwrap(pin)
        except ValueError:
            if limit and fails >= limit:
                self.wipe()
                raise Wiped("Too many wrong PINs — the vault was wiped. Restore from your seed phrase.")
            raise BadPin(limit - fails if limit else None)
        con = self._db()
        try:
            self._put(con, "fails", b"0")
            con.commit()
        finally:
            con.close()
        return mk

    def attempts_left(self):
        if not self.initialized():
            return None
        con = self._db()
        try:
            fails = int(self._get(con, "fails", b"0"))
        finally:
            con.close()
        limit = self.settings().get("max_attempts", 5)
        return (limit - fails) if limit else None

    def unlock(self, pin: str):
        self._mk = bytearray(self._check(pin))

    def verify_pin(self, pin: str):
        """Re-check the PIN for a sensitive action (sign / show seed / wipe). Same attempt counting as unlock."""
        if not self.unlocked:
            raise Locked("Vault is locked.")
        self._check(pin)

    def lock(self):
        if self._mk is not None:
            for i in range(len(self._mk)):
                self._mk[i] = 0
        self._mk = None

    def change_pin(self, old: str, new: str):
        mk = self._check(old)
        salt, nonce = os.urandom(16), os.urandom(12)
        kek = self._kek(new, salt, SCRYPT)
        con = self._db()
        try:
            self._put(con, "kdf", json.dumps({**SCRYPT, "salt": salt.hex()}).encode())
            self._put(con, "wrapped_mk", nonce + _enc(kek, nonce, mk, b"vault:wrapped_mk"))
            con.commit()
        finally:
            con.close()

    def wipe(self):
        self.lock()
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, "r+b") as f:
                    n = os.path.getsize(self.db_path)
                    f.write(b"\x00" * n); f.flush(); os.fsync(f.fileno())
                os.remove(self.db_path)
        except OSError:
            pass
        self.device.destroy()

    # ---- settings (not secret) ----
    def settings(self) -> dict:
        con = self._db()
        try:
            raw = self._get(con, "settings")
        finally:
            con.close()
        s = dict(DEFAULT_SETTINGS)
        if raw:
            s.update(json.loads(raw))
        return s

    def set_settings(self, **kw):
        s = self.settings()
        s.update({k: v for k, v in kw.items() if k in DEFAULT_SETTINGS})
        con = self._db()
        try:
            self._put(con, "settings", json.dumps(s).encode())
            con.commit()
        finally:
            con.close()
        return s

    # ---- wallets ----
    def add_wallet(self, meta: dict, secret: dict) -> int:
        con = self._db()
        try:
            cur = con.execute("INSERT INTO wallets(created, meta, secret) VALUES(?,?,?)", (int(time.time()), b"", b""))
            wid = cur.lastrowid
            con.execute("UPDATE wallets SET meta=?, secret=? WHERE id=?",
                        (self._seal("wallets", wid, "meta", meta), self._seal("wallets", wid, "secret", secret), wid))
            con.commit()
            return wid
        finally:
            con.close()

    def list_wallets(self) -> list:
        """[{id, created, ...meta}]  — never touches the secret column."""
        con = self._db()
        try:
            rows = con.execute("SELECT id, created, meta FROM wallets ORDER BY id").fetchall()
        finally:
            con.close()
        return [{"id": i, "created": c, **self._open("wallets", i, "meta", m)} for i, c, m in rows]

    def get_secret(self, wid: int) -> dict:
        con = self._db()
        try:
            r = con.execute("SELECT secret FROM wallets WHERE id=?", (wid,)).fetchone()
        finally:
            con.close()
        if not r:
            raise StoreError("No such wallet.")
        return self._open("wallets", wid, "secret", r[0])

    def update_meta(self, wid: int, **kw):
        cur = next((w for w in self.list_wallets() if w["id"] == wid), None)
        if not cur:
            raise StoreError("No such wallet.")
        meta = {k: v for k, v in cur.items() if k not in ("id", "created")}
        meta.update(kw)
        con = self._db()
        try:
            con.execute("UPDATE wallets SET meta=? WHERE id=?", (self._seal("wallets", wid, "meta", meta), wid))
            con.commit()
        finally:
            con.close()

    def delete_wallet(self, wid: int):
        con = self._db()
        try:
            for t, col in (("wallets", "id"), ("sync", "wid"), ("history", "wid")):
                con.execute(f"DELETE FROM {t} WHERE {col}=?", (wid,))
            con.commit()
        finally:
            con.close()

    # ---- synced balances / history ----
    def set_sync(self, wid: int, data: dict):
        con = self._db()
        try:
            con.execute("INSERT OR REPLACE INTO sync(wid, data) VALUES(?,?)", (wid, self._seal("sync", wid, "data", data)))
            con.commit()
        finally:
            con.close()

    def get_sync(self, wid: int):
        con = self._db()
        try:
            r = con.execute("SELECT data FROM sync WHERE wid=?", (wid,)).fetchone()
        finally:
            con.close()
        return self._open("sync", wid, "data", r[0]) if r else None

    def add_history(self, wid: int, entry: dict):
        con = self._db()
        try:
            cur = con.execute("INSERT INTO history(wid, ts, data) VALUES(?,?,?)", (wid, int(time.time()), b""))
            hid = cur.lastrowid
            con.execute("UPDATE history SET data=? WHERE id=?", (self._seal("history", hid, "data", entry), hid))
            con.commit()
        finally:
            con.close()

    def list_history(self, wid=None, limit=100) -> list:
        con = self._db()
        try:
            q, args = "SELECT id, wid, ts, data FROM history", ()
            if wid is not None:
                q, args = q + " WHERE wid=?", (wid,)
            rows = con.execute(q + " ORDER BY id DESC LIMIT ?", args + (limit,)).fetchall()
        finally:
            con.close()
        return [{"id": i, "wid": w, "ts": t, **self._open("history", i, "data", d)} for i, w, t, d in rows]
