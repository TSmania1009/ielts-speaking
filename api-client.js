/* =====================================================================
 * CNSA IELTS — 서버 연결 (모든 화면이 함께 씀)
 *
 * 학생 자료는 학교 NAS에만 저장됩니다. 이 파일이 화면과 교내 PC 서버를 이어 줍니다.
 *  - 교사 PC(또는 등록된 교사 기기)에서 연 화면: 그 서버(/api)로 바로 보냄
 *  - GitHub에 올린 화면: 요청을 이 브라우저에서 암호화해 중계(Apps Script 우편함)에 맡김
 *      · 요청마다 새 AES-256 키를 만들고, 그 키를 교내 PC의 공개 열쇠(RSA-OAEP)로 잠급니다.
 *      · 응답도 같은 일회용 키로 잠겨 돌아오므로 이 브라우저만 풀 수 있습니다.
 *      · 중간의 Google은 암호문만 잠깐 보관하고, 내용(답안·녹음·로그인 정보)을 읽을 수 없습니다.
 *
 * 아래 두 값은 교내 PC의 "설정.cmd → 학생 화면 연결 정보 넣기"가 자동으로 채웁니다. 직접 고치지 마세요.
 * ===================================================================== */
(function () {
  'use strict';
  var RELAY_URL = 'https://script.google.com/macros/s/AKfycbwSA7e-vOip7kICgWrAHQgvgak-FgB4_vWVa647Vl1M3_Eay25qwmtRI7oZ1TkaupuySQ/exec';
  var PC_PUBLIC_KEY = 'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA5dPA+4WQbAIUmK+xgsUH54aK+zYSg4bg1ybUUdnXvhpVS+Ms1j4b32PHoSuPorHKcI8BTve63g5uLkBq6jjLmAjasJf44G+zGSYZCVjhqC6d4bsI2/jZ/t3uv3skYKFWHSiU1KQBlmAabUtl7cb8Je/2ax0NRBxoO7+o0ocsD6SAjpxIVWM0NJXaBwk8fOayegSVxsQlu887uGDGH4tIDhrTQ958aFXFnLJj8v208uCYgf1qi4CXf54i4qvZ3iDV06F+xwDT1Zeaf3JC/uqjE8IsClqaHZzsueHDMs9fP+jYIHc3iPRNurlbOW6qQFIvgdUWGi2RAW5x4yG0FIIFoZ0OsMM8twbXvtAhse89qegRa//SZfk5zqMje4MddblmcAEjmIzmPDzJrg/LDXzu6taoQK2hwNOof11Zu/JRY755lR/NvkWY43BCH3MM1TgKcDKu04l551lsEN8ainY6Kq164G3nZM4jNLyH6RH+rKWir7xW6fvIwTmoKg6nc/L1AgMBAAE=';

  var LOCAL = !!window.IELTS_LOCAL;   // 교내 PC 서버가 화면을 직접 줄 때 서버가 넣어 주는 표시
  var OFFLINE_MSG = '선생님 PC 서버가 지금 꺼져 있어서 저장하거나 불러올 수 없어요. 잠시 후 다시 시도해 주세요.';
  var SLOW_ACTIONS = /^(aiAnswer|aiOverall|wtAi|tgrowthAi)$/;   // Gemini 분석은 오래 걸릴 수 있음

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function hex(n) {
    var a = crypto.getRandomValues(new Uint8Array(n)), s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
  }
  function b64FromBuf(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function bufFromB64(b64) {
    var s = atob(b64), bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }

  /* ---------- 교사 PC에서 바로 ---------- */
  function direct(t, d, keepalive) {
    return fetch('/api', {
      method: 'POST', cache: 'no-store', keepalive: !!keepalive,
      headers: { 'Content-Type': 'application/json', 'X-IELTS-Local': '1' },
      body: JSON.stringify({ t: t, d: d })
    }).then(function (r) {
      if (r.status === 401) { location.reload(); throw new Error('등록되지 않은 기기입니다.'); }
      return r.json();
    });
  }

  /* ---------- 중계 (암호화) ---------- */
  var keyPromise = null;
  function publicKey() {
    if (!keyPromise) keyPromise = crypto.subtle.importKey('spki', bufFromB64(PC_PUBLIC_KEY), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    return keyPromise;
  }
  async function seal(t, d) {
    var aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    var rawKey = await crypto.subtle.exportKey('raw', aesKey);
    var lockedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, await publicKey(), rawKey);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var plain = new TextEncoder().encode(JSON.stringify({ t: t, d: d, ts: Date.now(), n: hex(16) }));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, plain);
    return { aesKey: aesKey, id: hex(16), env: JSON.stringify({ v: 1, k: b64FromBuf(lockedKey), iv: b64FromBuf(iv), c: b64FromBuf(ct) }) };
  }
  async function open(aesKey, envStr) {
    var env = JSON.parse(envStr);
    var out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bufFromB64(env.iv) }, aesKey, bufFromB64(env.c));
    return JSON.parse(new TextDecoder().decode(out));
  }

  function banner(offline) {
    var el = document.getElementById('ieltsOfflineBanner');
    if (!offline) { if (el) el.remove(); return; }
    if (el) return;
    el = document.createElement('div');
    el.id = 'ieltsOfflineBanner';
    el.setAttribute('role', 'status');
    el.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:10000;background:#8a5a00;color:#fff;padding:10px 16px;font-size:14px;line-height:1.5;text-align:center';
    el.textContent = OFFLINE_MSG;
    document.body.appendChild(el);
  }

  async function viaRelay(t, d) {
    if (!RELAY_URL || !PC_PUBLIC_KEY) throw new Error('서버 연결 정보가 아직 설정되지 않았습니다. 선생님께 알려 주세요. (api-client.js)');
    var s = await seal(t, d);
    var body = JSON.stringify({ a: 'submit', id: s.id, env: s.env });
    var r;
    try {
      r = await fetch(RELAY_URL, { method: 'POST', body: body }).then(function (x) { return x.json(); });
    } catch (e) {
      // 응답을 읽지 못함(일시적인 네트워크 문제 등): 같은 번호로 한 번 더 맡기고 결과를 기다립니다. 중계는 같은 번호를 두 번 받지 않습니다.
      try { await fetch(RELAY_URL, { method: 'POST', mode: 'no-cors', body: body }); } catch (_) {}
      r = { status: 'pending' };
    }
    var deadline = Date.now() + (SLOW_ACTIONS.test(String(d && d.action)) ? 240000 : 75000);
    while (r && r.status === 'pending') {
      if (Date.now() > deadline) throw new Error('선생님 PC 서버의 응답이 늦어지고 있어요. 잠시 후 다시 시도해 주세요.');
      try { r = await fetch(RELAY_URL + '?a=wait&id=' + s.id, { cache: 'no-store' }).then(function (x) { return x.json(); }); }
      catch (e) { await sleep(1500); r = { status: 'pending' }; }
    }
    if (r && r.status === 'offline') { banner(true); throw Object.assign(new Error(OFFLINE_MSG), { offline: true }); }
    if (!r || r.status !== 'ok') throw new Error((r && r.message) || '중계 서버 응답을 이해하지 못했어요. 페이지를 새로고침해 주세요.');
    banner(false);
    return open(s.aesKey, r.env);
  }

  function call(t, d) { return LOCAL ? direct(t, d) : viaRelay(t, d); }

  // 창을 닫을 때 보내는 저장 (응답을 기다리지 않음)
  function beacon(d) {
    if (LOCAL) { try { direct('post', d, true); } catch (_) {} return; }
    if (!RELAY_URL || !PC_PUBLIC_KEY) return;
    seal('post', d).then(function (s) {
      return fetch(RELAY_URL, { method: 'POST', mode: 'no-cors', keepalive: true, body: JSON.stringify({ a: 'submit', id: s.id, env: s.env }) });
    }).catch(function () {});
  }

  window.IELTS_API = {
    local: LOCAL,
    get: function (params) { return call('get', params || {}); },
    post: function (payload) { return call('post', payload || {}); },
    beacon: beacon
  };
})();
