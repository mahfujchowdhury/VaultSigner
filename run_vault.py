#!/usr/bin/env python3
"""
run_vault.py — desktop host for Vault Signer (HTML UI + Python core). Replaces the old Tkinter GUI.

    pip install pywebview embit pycryptodome eth_account cbor2 rlp qrcode
    python run_vault.py                 # data in ./vault_data   (or:  --data D:\\VaultData)
    python vault_selftest.py            # headless tests, no window

OFFLINE: Python may only talk to loopback (needed by pywebview's local UI server); everything else is blocked, and the page has a CSP with connect-src 'none'.
Camera: WebView2 asks permission once.  No camera?  Use "File / paste" on the scan screens (QR images work).
"""
import sys

import socket, ssl, http.client, urllib.request  # noqa: F401,E401  (import first, THEN restrict sockets)

# Offline guard: only loopback (127.0.0.1 / ::1 / localhost) is allowed. pywebview needs it to serve the local UI
# to its own window. Any other address -> RuntimeError. (The page itself also has a CSP with connect-src 'none'.)
_LOOP = ("127.0.0.1", "::1", "localhost", "")


def _blocked(what="network access"):
    raise RuntimeError(f"NETWORK DISABLED: Vault Signer is offline-only ({what})")


def _check(addr):
    host = addr[0] if isinstance(addr, tuple) else addr
    if isinstance(host, bytes):
        host = host.decode()
    if host not in _LOOP:
        _blocked(f"{host}")


_Real = socket.socket


class _LoopOnly(_Real):
    def connect(self, addr):
        _check(addr); return super().connect(addr)

    def connect_ex(self, addr):
        _check(addr); return super().connect_ex(addr)

    def bind(self, addr):
        _check(addr); return super().bind(addr)

    def sendto(self, data, *a):
        _check(a[-1]); return super().sendto(data, *a)


socket.socket = _LoopOnly
_real_gai, _real_ghbn = socket.getaddrinfo, socket.gethostbyname


def _gai(host, *a, **k):
    if host not in _LOOP and host is not None:
        _blocked(f"DNS lookup of {host}")
    return _real_gai(host, *a, **k)


def _ghbn(host):
    if host not in _LOOP:
        _blocked(f"DNS lookup of {host}")
    return _real_ghbn(host)


socket.getaddrinfo, socket.gethostbyname = _gai, _ghbn
socket.gethostbyname_ex = lambda h: _blocked("DNS lookup")

import argparse, os

HERE = os.path.dirname(os.path.abspath(__file__))


class Host:
    def __init__(self):
        self.window = None

    def save_file(self, name, data):
        import webview
        dlg = webview.SAVE_DIALOG if not hasattr(webview, "FileDialog") else webview.FileDialog.SAVE
        r = self.window.create_file_dialog(dlg, save_filename=name)
        if not r:
            return None
        path = r if isinstance(r, str) else r[0]
        with open(path, "wb" if isinstance(data, (bytes, bytearray)) else "w") as f:
            f.write(data)
        return os.path.basename(path)


class Bridge:
    """Exposed to JS as window.pywebview.api.call(method, jsonArgs) -> jsonString"""
    def __init__(self, api):
        self._api = api

    def call(self, method, args="{}"):
        return self._api.dispatch(method, args)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "vault_data"))
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    import webview
    from vault_api import VaultApi
    host = Host()
    api = VaultApi(a.data, host=host)
    window = webview.create_window("Vault Signer — OFFLINE", url=os.path.join(HERE, "web", "Vault.html"),
                                   js_api=Bridge(api), width=430, height=860, min_size=(380, 700))
    host.window = window
    webview.start(debug=a.debug, private_mode=True)


if __name__ == "__main__":
    main()
