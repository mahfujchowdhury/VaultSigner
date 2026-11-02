/* vault_app.js — wires the Vault Signer design to the Python core.
   Loaded AFTER the design script; it overrides the design's demo functions (same names).
   Host contract: window.pywebview.api.call(method, jsonArgs) -> Promise<jsonString>      (desktop, run_vault.py)
                  window.VaultAndroid.call(method, jsonArgs)   -> jsonString               (Android WebView + Chaquopy)
   Secrets never persist in JS: seed words live in a variable only while shown; PINs are cleared after use. */
(function () {
'use strict';
var $ = function (id) { return document.getElementById(id); };
var S = { initialized: false, unlocked: false, wallets: [], settings: {}, caps: {} };
var pinPurpose = null, oldPin = '', draftWords = null, draftQuiz = [], lastReviewText = '', lastSigned = null,
    lastPair = null, lastExport = null, scanStream = null, scanPurpose = null, scanTimer = null, lastScanText = '',
    anims = {}, lastActive = Date.now(), reviewInfo = null;
window.pin4 = '';

/* ------------------------------ host bridge ------------------------------ */
function call(method, args) {
  var j = JSON.stringify(args || {}), p;
  if (window.pywebview && window.pywebview.api) p = window.pywebview.api.call(method, j);
  else if (window.VaultAndroid) p = Promise.resolve(window.VaultAndroid.call(method, j));
  else return Promise.reject(new Error('No Python host. Start the app with run_vault.py.'));
  return Promise.resolve(p).then(function (raw) {
    var r = JSON.parse(raw);
    if (!r.ok) { var e = new Error(r.error); e.code = r.code; e.left = r.attempts_left; throw e; }
    return r.data;
  });
}
function hostReady() {
  return new Promise(function (res) {
    if ((window.pywebview && window.pywebview.api) || window.VaultAndroid) return res();
    window.addEventListener('pywebviewready', function () { res(); });
    setTimeout(res, 4000);
  });
}
function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function fail(e) {
  if (e && e.code === 'locked') { lockUI(); return; }
  if (e && e.code === 'wiped') { applyState({ initialized: false, unlocked: false, wallets: [] }); goTo('screen-onboard'); }
  showToast((e && e.message) || 'Something went wrong');
}
function curWid() { return ACC[curAcc] ? ACC[curAcc].id : null; }

/* ------------------------------ state ------------------------------ */
function applyState(st) {
  S = st;
  var keep = ACC[curAcc] ? ACC[curAcc].id : null;
  ACC = st.wallets || [];
  var want = st.new_wid != null ? st.new_wid : (st.synced_wid != null ? st.synced_wid : keep);
  var i = ACC.findIndex(function (a) { return a.id === want; });
  curAcc = i >= 0 ? i : 0;
  syncBtcType();
  if (ACC.length) { renderAcc(); } else { clearDash(); }
  renderSettings();
}
function clearDash() {
  ['accName', 'accAddr', 'balcoin', 'receiveAddress'].forEach(function (k) { if ($(k)) $(k).textContent = ''; });
  if ($('balanceval')) $('balanceval').textContent = '—';
  if ($('assetList')) $('assetList').innerHTML = '';
  if ($('acctList')) $('acctList').innerHTML = '';
}
function init() {
  hostReady().then(function () { return call('status'); }).then(function (st) {
    applyState(st);
    if (st.initialized && !st.unlocked) { showUnlock(); }
    else if (st.initialized && st.unlocked) { goTo('screen-dashboard'); }
    else { goTo('screen-onboard'); }
    if (!st.caps.btc || !st.caps.eth) showToast((!st.caps.btc ? 'Bitcoin' : 'Ethereum') + ' engine unavailable — see console');
  }).catch(function (e) {
    goTo('screen-onboard'); showToast(e.message);
  });
}

/* ------------------------------ navigation hooks ------------------------------ */
var _goTo = window.goTo;
window.goTo = function (id) {
  if (id !== 'screen-signed') stopAnim('signed');
  if (id !== 'screen-pair-detail') stopAnim('pd');
  if (id !== 'screen-scan-sign' && id !== 'screen-sync') stopScan();
  _goTo(id);
  if (id === 'screen-receive') renderReceive();
  else if (id === 'screen-pair') renderPair();
  else if (id === 'screen-history') loadHistory();
  else if (id === 'screen-settings') renderSettings();
  else if (id === 'screen-addrtype') renderAddrType();
  else if (id === 'screen-scan-sign') prepScan('sign');
  else if (id === 'screen-sync') prepScan('sync');
};
function showUnlock() {
  pin4 = ''; updatePinDots(4); $('unlockErr').textContent = '';
  var l = S.attempts_left;
  $('unlockSub').textContent = (l != null && l < (S.settings.max_attempts || 5)) ? l + ' attempt' + (l === 1 ? '' : 's') + ' left before the vault is wiped' : 'Enter your PIN to unlock';
  goTo('screen-unlock');
}

/* ------------------------------ lock / auto-lock ------------------------------ */
function lockUI() {
  stopScan(); stopAnim('signed'); stopAnim('pd');
  draftWords = null; lastSigned = null; lastPair = null; lastExport = null; reviewInfo = null;
  ['seedgrid', 'phraseGrid'].forEach(function (g) { if ($(g)) $(g).innerHTML = ''; });
  ['signedQR', 'pdQR', 'exportQR', 'reviewCard'].forEach(function (g) { if ($(g)) $(g).innerHTML = ''; });
  document.querySelectorAll('.modal-overlay.show').forEach(function (m) { m.classList.remove('show'); });
  S.unlocked = false; ACC = []; curAcc = 0; clearDash();
  if (S.initialized) showUnlock(); else goTo('screen-onboard');
}
window.doLock = function () { call('lock').then(function (st) { S.unlocked = false; S.attempts_left = st.attempts_left; lockUI(); }).catch(fail); };
function idleCheck() {
  var limit = (S.settings && S.settings.autolock) || 0;
  if (S.unlocked && limit && Date.now() - lastActive > limit * 1000) window.doLock();
}
['pointerdown', 'keydown', 'touchstart'].forEach(function (ev) {
  document.addEventListener(ev, function () {
    var now = Date.now();
    if (S.unlocked && now - lastActive > 5000) call('touch').catch(function () {});
    lastActive = now;
  }, true);
});
setInterval(idleCheck, 2000);
document.addEventListener('visibilitychange', function () { if (!document.hidden) idleCheck(); });

/* ------------------------------ PIN entry ------------------------------ */
function clearPin(step) { window['pin' + step] = ''; updatePinDots(step); }
function setPinText(step, title, sub) {
  if ($('pinTitle' + step) && title) $('pinTitle' + step).textContent = title;
  if ($('pinSub' + step) && sub) $('pinSub' + step).textContent = sub;
}
window.handlePinComplete = function (step) {
  if (step === 1) {
    var p = pin1;
    call('setup_check', { pin: p }).then(function (r) {
      if (r.problem) { $('pinSetupErr').textContent = r.problem; clearPin(1); return; }
      $('pinSetupErr').textContent = ''; pin2 = ''; updatePinDots(2); goTo('screen-pin-confirm');
    }).catch(fail);
  } else if (step === 2) {
    if (pin2 !== pin1) {
      $('pinMatchErr').style.display = 'block'; clearPin(2);
      setTimeout(function () { $('pinMatchErr').style.display = 'none'; }, 2000); return;
    }
    var newPin = pin1;
    var job = pinPurpose === 'change' ? call('change_pin', { old: oldPin, new: newPin }).then(function () { showToast('PIN changed'); goTo('screen-settings'); })
      : call('commit_draft', { pin: newPin }).then(function (st) { draftWords = null; applyState(st); goTo('screen-dashboard'); showToast('Wallet created — vault encrypted'); });
    job.then(function () { pin1 = pin2 = oldPin = ''; pinPurpose = null; updatePinDots(1); updatePinDots(2); })
      .catch(function (e) { clearPin(2); if (e.code === 'duplicate' || e.code === 'no_draft') goTo('screen-onboard'); fail(e); });
  } else if (step === 3) {
    var pin = pin3; $('pinSignErr').textContent = 'Verifying…';
    var done = function () { clearPin(3); $('pinSignErr').textContent = ''; };
    var bad = function (e) {
      clearPin(3);
      if (e.code === 'bad_pin') { $('pinSignErr').textContent = e.message; }
      else { $('pinSignErr').textContent = ''; fail(e); }
    };
    if (pinPurpose === 'sign') {
      call('sign', { pin: pin }).then(function (res) { done(); showSigned(res); }).catch(bad);
    } else if (pinPurpose === 'phrase') {
      call('get_phrase', { pin: pin, wid: curWid() }).then(function (r) { done(); openPhrase(r); }).catch(bad);
    } else if (pinPurpose === 'wipe') {
      call('wipe', { pin: pin }).then(function (st) { done(); applyState(st); lockUI(); showToast('Vault wiped'); }).catch(bad);
    } else if (pinPurpose === 'changeOld') {
      call('verify_pin', { pin: pin }).then(function () {
        oldPin = pin; done(); pinPurpose = 'change';
        setPinText(1, 'New PIN', 'Choose a new 6-digit PIN'); setPinText(2, 'Confirm new PIN');
        pin1 = pin2 = ''; updatePinDots(1); updatePinDots(2); goTo('screen-pin-setup');
      }).catch(bad);
    }
  } else if (step === 4) {
    var pn = pin4; $('unlockErr').style.color = 'var(--mist)'; $('unlockErr').textContent = 'Unlocking…';
    call('unlock', { pin: pn }).then(function (st) {
      clearPin(4); $('unlockErr').textContent = ''; lastActive = Date.now(); applyState(st); goTo('screen-dashboard');
    }).catch(function (e) {
      clearPin(4); $('unlockErr').style.color = 'var(--danger)';
      if (e.code === 'wiped') { $('unlockErr').textContent = ''; fail(e); return; }
      S.attempts_left = e.left; $('unlockErr').textContent = e.message;
    });
  }
};
function askPin(purpose, title, sub) {
  pinPurpose = purpose; clearPin(3); $('pinSignErr').textContent = '';
  setPinText(3, title, sub); goTo('screen-pin-sign');
}
window.forgotPin = function () {
  showWipeModal('forgot');
};

/* ------------------------------ create / import ------------------------------ */
window.togglePassCreate = function (el) {
  el.classList.toggle('active'); $('createPassWrap').classList.toggle('hide', !el.classList.contains('active'));
  if (!el.classList.contains('active')) $('createPass').value = '';
};
window.startCreate = function () {
  var pp = $('ppillCreate').classList.contains('active') ? $('createPass').value : '';
  $('genBtn').disabled = true;
  call('new_wallet', { passphrase: pp, name: $('createName').value }).then(function (d) {
    draftWords = d.words; draftQuiz = d.quiz;
    buildGrid('seedgrid'); seedRevealed = false; $('seedgrid').style.filter = 'blur(6px)';
    $('revealbtn').innerHTML = '<i class="ti ti-eye"></i> Reveal words';
    var cb = document.querySelector('#backupcheck input'); if (cb) cb.checked = false; $('seedContinueBtn').disabled = true;
    [1, 2, 3].forEach(function (n) {
      var pos = draftQuiz[n - 1] + 1; $('qn' + n).textContent = '#' + pos; $('quiz' + n).placeholder = 'Type word #' + pos + ' here';
      $('quiz' + n).value = ''; $('quiz' + n + 'err').style.display = 'none';
    });
    $('quizBtn').disabled = true; goTo('screen-seed');
  }).catch(fail).then(function () { $('genBtn').disabled = false; });
};
window.buildGrid = function (id) {
  var g = $(id); if (!g) return; g.innerHTML = '';
  (id === 'seedgrid' ? draftWords : (window._phraseWords || [])) && (id === 'seedgrid' ? draftWords : window._phraseWords).forEach(function (w, i) {
    var d = document.createElement('div'); d.className = 'seed-word';
    d.innerHTML = '<span class="mono" style="color:var(--faint);">' + (i + 1) + '</span><span class="mono">' + esc(w) + '</span>'; g.appendChild(d);
  });
};
var quizOk = [false, false, false];
window.checkQuiz = function () {
  [1, 2, 3].forEach(function (n) {
    var v = $('quiz' + n).value.trim().toLowerCase();
    if (!v) { quizOk[n - 1] = false; $('quiz' + n + 'err').style.display = 'none'; refreshQuizBtn(); return; }
    call('check_quiz', { index: draftQuiz[n - 1], word: v }).then(function (r) {
      if ($('quiz' + n).value.trim().toLowerCase() !== v) return;
      quizOk[n - 1] = r.ok; $('quiz' + n + 'err').style.display = r.ok ? 'none' : 'block'; refreshQuizBtn();
    }).catch(fail);
  });
};
function refreshQuizBtn() { $('quizBtn').disabled = !(quizOk[0] && quizOk[1] && quizOk[2]); }
window.afterBackup = function () {
  quizOk = [false, false, false];
  if (S.initialized) {                                  // adding another account to an unlocked vault
    call('commit_draft').then(function (st) { draftWords = null; applyState(st); goTo('screen-dashboard'); showToast('Account added'); }).catch(fail);
  } else { pinPurpose = 'new'; resetPinScreens(); goTo('screen-pin-setup'); }
};
function resetPinScreens() {
  pin1 = pin2 = ''; updatePinDots(1); updatePinDots(2);
  setPinText(1, 'Set PIN', 'Choose a 6-digit PIN to protect this wallet'); setPinText(2, 'Confirm PIN');
  $('pinSetupErr').textContent = '';
}
window.checkImport = function () {
  var n = $('importSeed').value.trim().split(/[\s,]+/).filter(Boolean).length;
  $('importBtn').disabled = [12, 15, 18, 21, 24].indexOf(n) < 0;
};
window.doImport = function () {
  $('importBtn').disabled = true;
  call('import_wallet', { words: $('importSeed').value, passphrase: $('importPass').value, name: $('importName').value }).then(function () {
    $('importSeed').value = ''; $('importPass').value = '';
    if (S.initialized) {
      return call('commit_draft').then(function (st) { applyState(st); goTo('screen-dashboard'); showToast('Account imported'); });
    }
    pinPurpose = 'new'; resetPinScreens(); goTo('screen-pin-setup');
  }).catch(fail).then(function () { checkImport(); });
};

/* ------------------------------ dashboard / receive ------------------------------ */
/* ------------------------------ Bitcoin address type (per account, stored encrypted) ------------------------------ */
function syncBtcType() { window.btcType = (ACC[curAcc] && ACC[curAcc].ty) || 0; }
window.btcAddr = function (acc, t) {                       // real addresses from the backend (m/84', m/49', m/86', m/44')
  var a = ACC[acc]; if (!a || !a.bt) return '';
  return a.bt[BTC_TYPES[t].k] || '';
};
var _setAcc = window.setAcc;
window.setAcc = function (i) { if (ACC[i]) window.btcType = ACC[i].ty || 0; _setAcc(i); };
window.pickBtcType = function (i) {
  var a = ACC[curAcc]; if (!a || i === window.btcType) return;
  call('set_btc_type', { wid: a.id, index: i }).then(function (st) {
    applyState(st); renderAddrType(); showToast('Address type: ' + BTC_TYPES[i].short);
  }).catch(fail);
};
window.copyTypeAddr = function (i) { var ad = btcAddr(curAcc, i); if (ad) { copyText(ad); showToast('Address copied'); } };
window.renderReceive = function () {
  if (!ACC[curAcc] || !$('rcvQR')) return;
  var net = NET[selNet], ad = curAddr();
  $('rcvCoin').outerHTML = coinHTML(net.ic, 24).replace('class="coin"', 'id="rcvCoin" class="coin"');
  $('rcvNetName').textContent = net.n; $('receiveAddress').textContent = ad || '—';
  var q = $('rcvQR'); q.className = 'qr-box'; q.style.cssText = 'width:180px;height:180px;'; q.innerHTML = '';
  if (ad) call('qr', { text: ad }).then(function (r) { if (curAddr() === ad) q.innerHTML = r.svg; }).catch(function () {});
  $('rcvNote').textContent = net.test ? 'Testnet address — only send test coins here.' :
    (selNet === 'bnb' ? 'BNB Smart Chain uses the same address as Ethereum.' :
      (selNet === 'eth' ? 'Send only ETH and ERC-20 tokens to this address.' : 'Send only Bitcoin (BTC) to this address.'));
};
window.copyAddress = function () {
  var a = $('receiveAddress').textContent; copyText(a); showToast('Address copied');
};
function copyText(t) {
  try { navigator.clipboard.writeText(t).catch(function () { legacyCopy(t); }); } catch (e) { legacyCopy(t); }
}
function legacyCopy(t) {
  var ta = document.createElement('textarea'); ta.value = t; ta.style.cssText = 'position:fixed;opacity:0;';
  document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) {} ta.remove();
}

/* ------------------------------ scanning (camera / file / paste) ------------------------------ */
function scanStatus(p, t, err) { var el = $('scanStatus-' + p); if (el) { el.textContent = t; el.style.color = err ? 'var(--danger)' : 'var(--faint)'; } }
function prepScan(p) {
  call('scan_reset').catch(function () {}); lastScanText = '';
  scanStatus(p, 'Camera off'); $('scanBtn-' + p).disabled = false; $('scanBtn-' + p).textContent = 'Start camera';
  $('scanVideo-' + p).classList.add('hide'); $('scanIcon-' + p).classList.remove('hide');
  var ta = $('paste-' + p); if (ta) ta.value = ''; $(p + 'FileBtn').disabled = true;
  var d = $(p + 'Drop'); if (d) { d.classList.remove('has'); $(p + 'DropTxt').innerHTML = 'Tap to choose ' + (p === 'sign' ? 'the request' : 'the sync file') + '<br/><span class="mono" style="font-size:10px;color:var(--faint);">file or QR image (PNG / JPG)</span>'; }
}
window.startScan = function (p) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { scanStatus(p, 'No camera API here — use File / paste', true); return; }
  stopScan(); scanPurpose = p; call('scan_reset').catch(function () {}); lastScanText = '';
  scanStatus(p, 'Starting camera…');
  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false }).then(function (stream) {
    scanStream = stream; var v = $('scanVideo-' + p); v.srcObject = stream; v.classList.remove('hide'); $('scanIcon-' + p).classList.add('hide');
    $('scanBtn-' + p).textContent = 'Stop camera'; $('scanBtn-' + p).onclick = function () { stopScan(); prepScan(p); $('scanBtn-' + p).onclick = function () { startScan(p); }; };
    return v.play();
  }).then(function () { scanStatus(p, 'Point at the QR…'); scanLoop(p); })
    .catch(function (e) { scanStatus(p, 'Camera unavailable (' + (e.name || e.message) + ') — use File / paste', true); stopScan(); });
};
window.stopScan = function () {
  if (scanTimer) { clearTimeout(scanTimer); scanTimer = null; }
  if (scanStream) { scanStream.getTracks().forEach(function (t) { t.stop(); }); scanStream = null; }
  ['sign', 'sync'].forEach(function (p) { var v = $('scanVideo-' + p); if (v) { v.srcObject = null; v.classList.add('hide'); } var i = $('scanIcon-' + p); if (i) i.classList.remove('hide'); });
};
window.leaveScan = function (to) { stopScan(); goTo(to); };
function scanLoop(p) {
  var v = $('scanVideo-' + p), cvs = document.createElement('canvas'), ctx = cvs.getContext('2d', { willReadFrequently: true });
  (function tick() {
    if (!scanStream) return;
    if (v.readyState >= 2 && v.videoWidth) {
      var sc = Math.min(1, 720 / v.videoWidth); cvs.width = Math.round(v.videoWidth * sc); cvs.height = Math.round(v.videoHeight * sc);
      ctx.drawImage(v, 0, 0, cvs.width, cvs.height);
      var img = ctx.getImageData(0, 0, cvs.width, cvs.height), code = window.jsQR && jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data && code.data !== lastScanText) { lastScanText = code.data; feedText(p, code.data, true); }
    }
    scanTimer = setTimeout(tick, 90);
  })();
}
function feedText(p, text, fromCamera) {
  return call('scan_feed', { text: text }).then(function (r) {
    if (r.error) { scanStatus(p, r.error, true); return false; }
    if (r.progress) { scanStatus(p, 'Fragments ' + r.progress[0] + ' / ' + r.progress[1] + ' — keep scanning'); return false; }
    if (r.done) { stopScan(); scanDone(p, r.text); return true; }
    return false;
  }).catch(fail);
}
function scanDone(p, text) {
  if (p === 'sign') reviewText(text);
  else call('import_sync', { text: text, wid: curWid() }).then(function (st) { applyState(st); showToast('Balances synced'); goTo('screen-dashboard'); }).catch(function (e) { scanStatus('sync', e.message, true); fail(e); });
}
window.pasteChanged = function (p) { $(p + 'FileBtn').disabled = !$('paste-' + p).value.trim(); };
window.submitPaste = function (p) {
  var lines = $('paste-' + p).value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
  call('scan_reset').then(function () {
    return lines.reduce(function (pr, l) { return pr.then(function (done) { return done ? true : feedText(p, l); }); }, Promise.resolve(false));
  }).then(function (done) { if (!done) scanStatus(p, 'Incomplete — paste every fragment (or the full text)', true), showToast('Incomplete input'); });
};
window.loadFiles = function (p, input) {
  var files = Array.prototype.slice.call(input.files || []); input.value = '';
  if (!files.length) return;
  call('scan_reset').then(function () {
    return files.reduce(function (pr, f) { return pr.then(function (done) { return done ? true : readOne(p, f); }); }, Promise.resolve(false));
  }).then(function (done) {
    $(p + 'Drop').classList.add('has'); $(p + 'DropTxt').innerHTML = '<span class="mono">' + esc(files.map(function (f) { return f.name; }).join(', ')) + '</span>';
    if (!done) { scanStatus(p, 'File read, but the request is incomplete', true); showToast('Incomplete — add the remaining files / fragments'); }
  }).catch(fail);
};
function readOne(p, f) {
  if (/^image\//.test(f.type)) {
    return createImageBitmap(f).then(function (bm) {
      var c = document.createElement('canvas'); c.width = bm.width; c.height = bm.height; var x = c.getContext('2d'); x.drawImage(bm, 0, 0);
      var img = x.getImageData(0, 0, c.width, c.height), code = window.jsQR && jsQR(img.data, img.width, img.height);
      if (!code) { showToast('No QR found in ' + f.name); return false; }
      return feedText(p, code.data);
    });
  }
  return f.arrayBuffer().then(function (buf) {
    var u = new Uint8Array(buf);
    if (u.length > 5 && u[0] === 0x70 && u[1] === 0x73 && u[2] === 0x62 && u[3] === 0x74 && u[4] === 0xff) {     // binary PSBT -> base64
      var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
      return feedText(p, btoa(s));
    }
    var lines = new TextDecoder().decode(u).split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (lines.length === 1 || p === 'sync') return feedText(p, lines.join('\n'));
    return lines.reduce(function (pr, l) { return pr.then(function (d) { return d ? true : feedText(p, l); }); }, Promise.resolve(false));
  });
}

/* ------------------------------ review / sign ------------------------------ */
function reviewText(text, unsafe) {
  lastReviewText = text;
  call('review', { text: text, wid: curWid(), net: selNet, allow_unsafe: !!unsafe }).then(function (rv) {
    reviewInfo = rv;
    if (rv.net_key && rv.net_key !== selNet && NET[rv.net_key]) { selNet = rv.net_key; renderNets(); }
    renderReview(rv); goTo('screen-review');
  }).catch(function (e) { scanStatus('sign', e.message, true); fail(e); });
}
function renderReview(rv) {
  $('reviewReal').innerHTML = rv.real
    ? '<div class="rv-box real"><i class="ti ti-alert-octagon"></i><span><b>REAL FUNDS</b> — ' + esc(rv.network) + '. This moves real money.</span></div>'
    : '<div class="rv-box test"><i class="ti ti-flask"></i><span>Test network — ' + esc(rv.network) + '. No real value.</span></div>';
  $('reviewCard').innerHTML = rv.rows.map(function (r) {
    return '<div class="rv-row"><span class="k">' + esc(r.k) + '</span><span class="v' + (r.mono ? ' mono' : '') + (r.long ? ' long' : '') + (r.strong ? ' strong' : '') + (r.accent ? ' accent' : '') + '">' + esc(r.v) + '</span></div>';
  }).join('');
  $('reviewWarn').innerHTML = rv.errors.map(function (e) { return '<div class="rv-box err"><i class="ti ti-circle-x"></i><span>' + esc(e) + '</span></div>'; }).join('') +
    rv.warnings.map(function (w) { return '<div class="rv-box warn"><i class="ti ti-alert-triangle"></i><span>' + esc(w) + '</span></div>'; }).join('');
  var c = $('reviewCalls'); c.textContent = rv.calls || ''; c.classList.toggle('hide', !rv.calls);
  $('reviewDetail').textContent = rv.detail || ''; $('reviewDetail').classList.add('hide');
  $('signBtn').disabled = !rv.can_sign; $('unsafeBtn').classList.toggle('hide', !rv.unsafe_hint);
}
window.toggleDetail = function () { $('reviewDetail').classList.toggle('hide'); };
window.allowUnsafe = function () {
  if (confirm('This PSBT does not include the full previous transactions, so the signer cannot prove the amounts. Only continue if you trust the app that created it and have checked recipient and amount.')) reviewText(lastReviewText, true);
};
window.rejectReview = function () { call('cancel_review').catch(function () {}); reviewInfo = null; goTo('screen-scan-sign'); };
window.beginSign = function () { if (reviewInfo && reviewInfo.can_sign) askPin('sign', 'Enter PIN to sign', 'Confirm with your PIN'); };
window.simulateScan = function () { goTo('screen-scan-sign'); };

/* ------------------------------ signed ------------------------------ */
function stopAnim(k) { if (anims[k]) { clearInterval(anims[k]); anims[k] = null; } }
function playFrames(k, boxId, metaId, svgs, frames) {
  stopAnim(k); var i = 0, box = $(boxId), meta = $(metaId);
  function show() { box.innerHTML = svgs[i]; meta.textContent = svgs.length > 1 ? 'Frame ' + (i + 1) + ' / ' + svgs.length + ' — keep it in view' : ''; i = (i + 1) % svgs.length; }
  show(); if (svgs.length > 1) anims[k] = setInterval(show, 450);
}
function showSigned(res) {
  lastSigned = res; $('signedNote').textContent = res.note; playFrames('signed', 'signedQR', 'signedMeta', res.svgs, res.frames);
  showToast('Transaction signed'); setTimeout(function () { goTo('screen-signed'); }, 300);
}
window.copySigned = function () { if (lastSigned) { copyText(lastSigned.copy); showToast('Copied'); } };
window.saveSigned = function () {
  call('save_signed').then(function (r) { showToast(r.path ? 'Saved ' + r.path : 'Cancelled'); }).catch(function (e) { showToast(e.message); });
};
window.doneSigned = function () { lastSigned = null; $('signedQR').innerHTML = ''; goTo('screen-dashboard'); };

/* ------------------------------ history ------------------------------ */
function loadHistory() {
  var box = $('histList'); if (!ACC[curAcc]) { box.innerHTML = ''; return; }
  call('history', { wid: curWid() }).then(function (r) {
    if (!r.items.length) { box.innerHTML = '<p style="font-size:12px;color:var(--faint);text-align:center;margin:18px 0;">Nothing here yet</p>'; return; }
    box.innerHTML = r.items.map(function (h) {
      var col = h.dir === 'in' ? 'secure' : h.dir === 'out' ? 'danger' : 'signal', ic = h.dir === 'in' ? 'arrow-down-left' : h.dir === 'out' ? 'arrow-up-right' : 'signature';
      return '<div class="asset-row"><div style="display:flex;align-items:center;gap:10px;"><div style="width:32px;height:32px;border-radius:50%;background:var(--' + col + '-dim);display:flex;align-items:center;justify-content:center;"><i class="ti ti-' + ic + '" style="color:var(--' + col + ');font-size:14px;"></i></div><div><p style="font-size:12px;margin:0;">' + esc(h.title) + '</p><p class="mono" style="font-size:10px;color:var(--faint);margin:0;">' + new Date(h.ts * 1000).toLocaleString() + (h.sub ? ' · ' + esc(h.sub) : '') + '</p></div></div><span class="mono" style="font-size:12px;color:var(--' + col + ');">' + esc(h.amt) + '</span></div>';
    }).join('');
  }).catch(fail);
}

/* ------------------------------ pairing / export ------------------------------ */
var pdNetsSel = [];
(function patchApps() {
  APPS.forEach(function (a) { a.nets = a.nets.filter(function (k) { return k !== 'sol'; }); });
  APPS.splice(4, 0, { id: 'us', n: 'UniSat / Sparrow / BlueWallet', l: 'U', c: '#F7931A', p: 'Keystone UR crypto-account (BTC)', nets: ['btc'],
    st: ['Open the wallet → Connect hardware wallet', 'Choose Keystone / QR-based', 'Scan this animated QR'] });
  APPS[0].p = 'Vault public-key JSON (QR / file)'; APPS[APPS.length - 1].p = 'Public-key JSON file';
})();
function btcNetKey() { return NET[selNet].ic.indexOf('btc') === 0 ? selNet : 'btc'; }
window.openPair = function (id) {
  curApp = APPS.filter(function (a) { return a.id === id; })[0]; var a = curApp;
  $('pdIco').textContent = a.l; $('pdIco').style.background = a.c; $('pdIco').style.color = '#fff';
  $('pdTitle').textContent = a.n; $('pdProto').textContent = a.p;
  pdNetsSel = a.nets.slice();
  $('pdNets').innerHTML = a.nets.map(function (k) { return '<span class="pill active" data-k="' + k + '" onclick="togglePdNet(this)">' + PAIRN[k] + '</span>'; }).join('');
  $('pdSteps').innerHTML = a.st.map(function (t, i) { return '<div class="sign-flow-step" style="padding:10px;margin-bottom:6px;"><div class="step-num">' + (i + 1) + '</div><span style="font-size:12px;">' + esc(t) + '</span></div>'; }).join('');
  $('pdSave').classList.toggle('hide', !(a.id === 'vw' || a.id === 'ot'));
  goTo('screen-pair-detail'); loadPair();
};
window.togglePdNet = function (el) {
  el.classList.toggle('active'); pdNetsSel = Array.prototype.map.call(document.querySelectorAll('#pdNets .pill.active'), function (x) { return x.getAttribute('data-k'); });
  loadPair();
};
function loadPair() {
  $('pdNotes').innerHTML = ''; $('pdMeta').textContent = 'Generating…'; $('pdQR').innerHTML = ''; stopAnim('pd');
  call('pair', { app: curApp.id, wid: curWid(), nets: pdNetsSel, btc_net: btcNetKey() }).then(function (r) {
    lastPair = r; playFrames('pd', 'pdQR', 'pdMeta', r.svgs, r.frames);
    $('pdNotes').innerHTML = (r.notes || []).map(function (n) { return '<div class="rv-box warn"><i class="ti ti-info-circle"></i><span>' + esc(n) + '</span></div>'; }).join('');
  }).catch(function (e) { $('pdMeta').textContent = e.message; if (e.code === 'locked') fail(e); });
}
window.leavePair = function () { stopAnim('pd'); lastPair = null; goTo('screen-pair'); };
window.savePairing = function () {
  if (!lastPair || !lastPair.text) return showToast('Nothing to save');
  call('save_text', { name: lastPair.file_name, text: lastPair.text }).then(function (r) { showToast(r.path ? 'Saved ' + r.path : 'Cancelled'); }).catch(function (e) { showToast(e.message); });
};
window.showExportModal = function () {
  $('exportModal').classList.add('show'); $('exportMeta').textContent = 'Generating…'; $('exportQR').innerHTML = '';
  call('export_pub', { wid: curWid(), btc_net: btcNetKey() }).then(function (r) {
    lastExport = r; playFrames('exp', 'exportQR', 'exportMeta', r.svgs, r.frames);
  }).catch(function (e) { $('exportMeta').textContent = e.message; fail(e); });
};
window.closeExport = function () { stopAnim('exp'); lastExport = null; $('exportQR').innerHTML = ''; closeModal('exportModal'); };
window.copyExport = function () { if (lastExport) { copyText(lastExport.text); showToast('Copied public keys'); } };
window.saveExport = function () {
  if (!lastExport) return;
  call('save_text', { name: lastExport.file_name, text: lastExport.text }).then(function (r) { showToast(r.path ? 'Saved ' + r.path : 'Cancelled'); }).catch(function (e) { showToast(e.message); });
};

/* ------------------------------ settings ------------------------------ */
var AUTOLOCK = [[30, '30 seconds'], [60, '1 minute'], [300, '5 minutes'], [0, 'Never']], ATTEMPTS = [[5, '5 attempts'], [10, '10 attempts'], [0, 'Off']];
function label(list, v) { var m = list.filter(function (x) { return x[0] === v; })[0]; return m ? m[1] : String(v); }
window.renderSettings = function () {
  if (!$('autolockVal')) return; var s = S.settings || {};
  $('autolockVal').textContent = label(AUTOLOCK, s.autolock); $('attemptsVal').textContent = label(ATTEMPTS, s.max_attempts);
  $('hwToggle').classList.toggle('on', s.btc_hw_mode !== false);
};
function cycle(list, key) {
  var cur = (S.settings || {})[key], i = list.findIndex(function (x) { return x[0] === cur; }), nx = list[(i + 1) % list.length][0];
  if (key === 'max_attempts' && nx === 0 && !confirm('Turning off the wipe limit lets someone with the device try PINs without limit. Continue?')) nx = list[0][0];
  call('set_setting', { key: key, value: nx }).then(function (s) { S.settings = s; renderSettings(); }).catch(fail);
}
window.cycleAutolock = function () { cycle(AUTOLOCK, 'autolock'); };
window.cycleAttempts = function () { cycle(ATTEMPTS, 'max_attempts'); };
window.toggleHw = function () {
  var on = !$('hwToggle').classList.contains('on');
  call('set_setting', { key: 'btc_hw_mode', value: on }).then(function (s) { S.settings = s; renderSettings(); showToast(on ? 'Signatures only — the wallet finalises' : 'Finalised PSBT output'); }).catch(fail);
};
window.startChangePin = function () { oldPin = ''; askPin('changeOld', 'Current PIN', 'Enter your current PIN'); };
window.showPhraseModal = function () { askPin('phrase', 'Enter PIN', 'Confirm to view the recovery phrase'); };
function openPhrase(r) {
  window._phraseWords = r.words; buildGrid('phraseGrid'); window._phraseWords = null; phraseRevealed = false;
  $('phraseGrid').style.filter = 'blur(6px)'; $('phraseRevealBtn').innerHTML = '<i class="ti ti-eye"></i> Reveal words';
  goTo('screen-settings'); $('phraseModal').classList.add('show');
}
var _closeModal = window.closeModal;
window.closeModal = function (id) { _closeModal(id); if (id === 'phraseModal') $('phraseGrid').innerHTML = ''; };
var wipeMode = 'wipe';
window.showWipeModal = function (mode) {
  wipeMode = mode || 'wipe';
  $('wipeTitle').textContent = wipeMode === 'forgot' ? 'Forgot your PIN?' : 'Wipe Wallet?';
  $('wipeText').textContent = wipeMode === 'forgot'
    ? 'There is no PIN reset. The only way forward is to erase this vault and restore your accounts from their seed phrases. Nothing on this device can be recovered.'
    : 'This permanently deletes every account and key from this device. Make sure you have your seed phrases backed up. Your PIN is required.';
  $('wipeModal').classList.add('show');
};
window.confirmWipe = function () {
  closeModal('wipeModal');
  if (wipeMode === 'forgot') {
    call('reset_vault').then(function (st) { applyState(st); lockUI(); showToast('Vault erased — restore from your seed'); }).catch(fail);
  } else { askPin('wipe', 'Enter PIN to wipe', 'This erases everything on this device'); }
};

/* ------------------------------ boot ------------------------------ */
document.addEventListener('DOMContentLoaded', init);
if (document.readyState !== 'loading') init();
})();
