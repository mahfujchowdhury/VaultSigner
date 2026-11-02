# Vault Signer — HTML UI + Python core (no Tkinter)

Run:        pip install -r requirements.txt  &&  python run_vault.py        (data: ./vault_data, or --data PATH)
Test:       python vault_selftest.py          (store + API, headless)

Files
  web/Vault.html, web/vault_app.js, web/assets/   UI (your design, wired; fonts/icons/jsQR bundled, no CDN)
  vault_api.py     one object the UI calls: dispatch(method, json) -> json   (all UI actions = m_<name>)
  vault_store.py   PIN + encrypted SQLite (AES-256-GCM rows, scrypt N=2^17, device secret, wipe after N bad PINs)
  btcv_lite.py, vault_core.py, evur.py, ur.py     your existing engines, unchanged
  run_vault.py     desktop host (pywebview/WebView2), Python sockets disabled, CSP connect-src 'none'

Security model
  PIN --scrypt--> --HKDF(device.key)--> KEK --unwrap--> random master key --> encrypts every row.
  Seeds are stored only inside the encrypted DB. PIN is re-checked (and counted) for: sign, view phrase, wipe, change PIN.
  IMPORTANT: a 6-digit PIN is only strong if device.key is NOT copied together with vault.db.
  On Android, replace FileDeviceSecret with a provider backed by Android Keystore (non-exportable key).
  Desktop: set VAULT_DEVICE_KEY to a path on a USB stick for real separation.

Android later: keep vault_api.py as is; expose  dispatch  through a @JavascriptInterface named VaultAndroid
  (Chaquopy: Python.getInstance().getModule("vault_api")), the JS already supports window.VaultAndroid.call(method, json).
  If you port the core to Java instead, keep the same method names/JSON so the HTML does not change.

Sync format (placeholder until the watch app exists):
  {"v":1,"fp":"<master fp hex, optional>","balances":{"btc":{"amt":0.1,"usd":6400}},"history":[{"ts":1760000000,"net":"btc","dir":"in","amt":"0.05 BTC"}]}
