#!/usr/bin/env python3
"""Create a static client-side form from a public, short-lived CI challenge.

No Apple credentials are accepted by this Python process. The generated HTML
encrypts them locally with WebCrypto and emits only an authenticated envelope.
"""
import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time


CHALLENGE_KEYS = frozenset({
    'version', 'purpose', 'run_id', 'phase', 'nonce', 'expires_at',
    'public_key_spki_pem', 'context_b64', 'allowed_payload',
})
MAX_CHALLENGE_BYTES = 16384


def _der_item(data, offset, tag):
    """Read one definite, minimally encoded DER item of an expected type."""
    if offset + 2 > len(data) or data[offset] != tag:
        raise ValueError('Challenge must contain a DER RSA public key')
    first = data[offset + 1]
    cursor = offset + 2
    if first & 0x80:
        width = first & 0x7f
        if not 1 <= width <= 2 or cursor + width > len(data) or data[cursor] == 0:
            raise ValueError('Invalid DER length')
        size = int.from_bytes(data[cursor:cursor + width], 'big')
        if size < 128:
            raise ValueError('Noncanonical DER length')
        cursor += width
    else:
        size = first
    end = cursor + size
    if end > len(data):
        raise ValueError('Truncated DER public key')
    return data[cursor:end], end


def _positive_der_integer(value):
    if not value or value[0] & 0x80:
        raise ValueError('Invalid RSA public integer')
    if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
        raise ValueError('Noncanonical RSA public integer')
    return int.from_bytes(value, 'big')


def validate_public_key(pem):
    """Accept only a bounded RSA SPKI public key, never a private key."""
    if not isinstance(pem, str) or len(pem) > 2048:
        raise ValueError('Challenge RSA public key is missing or too large')
    pem = pem.replace('\r\n', '\n')
    match = re.fullmatch(
        r'-----BEGIN PUBLIC KEY-----\n((?:[A-Za-z0-9+/=]{1,64}\n)+)'
        r'-----END PUBLIC KEY-----\n?', pem,
    )
    if match is None:
        raise ValueError('Challenge requires a public SPKI PEM key')
    try:
        der = base64.b64decode(match.group(1).replace('\n', ''), validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('Invalid public key base64') from error
    sequence, end = _der_item(der, 0, 0x30)
    if end != len(der):
        raise ValueError('Trailing public key data')
    algorithm, cursor = _der_item(sequence, 0, 0x30)
    if algorithm != bytes.fromhex('06092a864886f70d0101010500'):
        raise ValueError('Challenge public key must use RSA encryption')
    bits, end = _der_item(sequence, cursor, 0x03)
    if end != len(sequence) or not bits or bits[0] != 0:
        raise ValueError('Invalid public key bit string')
    rsa, end = _der_item(bits[1:], 0, 0x30)
    if end != len(bits) - 1:
        raise ValueError('Invalid RSA public key structure')
    modulus, cursor = _der_item(rsa, 0, 0x02)
    exponent, end = _der_item(rsa, cursor, 0x02)
    if end != len(rsa):
        raise ValueError('Trailing RSA public key data')
    modulus = _positive_der_integer(modulus)
    if not 2048 <= modulus.bit_length() <= 4096 or not modulus & 1:
        raise ValueError('RSA public key must have 2048 to 4096 bits')
    if _positive_der_integer(exponent) != 65537:
        raise ValueError('RSA public exponent must be 65537')
    return pem


def validate_challenge(challenge, now=None):
    """Validate the exact protocol, phase scope and remaining lifetime."""
    if not isinstance(challenge, dict) or set(challenge) != CHALLENGE_KEYS:
        raise ValueError('Unexpected challenge fields')
    if type(challenge['version']) is not int or challenge['version'] != 1:
        raise ValueError('Unsupported challenge version')
    if challenge['purpose'] != 'bereal-apple-auth':
        raise ValueError('Unexpected challenge purpose')
    run_id = challenge['run_id']
    if not isinstance(run_id, str) or re.fullmatch(r'[1-9][0-9]{0,23}', run_id) is None:
        raise ValueError('Invalid CI run identifier')
    phase = challenge['phase']
    if type(phase) is not int or not 0 <= phase <= 3:
        raise ValueError('Invalid authentication phase')
    allowed = 'credentials' if phase == 0 else 'two_factor'
    if challenge['allowed_payload'] != allowed:
        raise ValueError('Challenge payload does not match its phase')
    nonce = challenge['nonce']
    if not isinstance(nonce, str) or re.fullmatch(r'[0-9a-f]{64}', nonce) is None:
        raise ValueError('Invalid challenge nonce')
    expires_at = challenge['expires_at']
    if type(expires_at) is not int or not 0 < expires_at < 2 ** 53:
        raise ValueError('Invalid challenge expiry')
    now = int(time.time()) if now is None else now
    if not 0 < expires_at - now <= (2400 if phase == 0 else 600):
        raise ValueError('Challenge is expired or exceeds its phase lifetime')
    context = f'BeReal493AppleAuthRelayV1|{run_id}|{phase}|{nonce}|{expires_at}'.encode('utf-8')
    encoded_context = challenge['context_b64']
    if not isinstance(encoded_context, str) or encoded_context != base64.b64encode(context).decode('ascii'):
        raise ValueError('Challenge authenticated context does not match')
    result = dict(challenge)
    result['public_key_spki_pem'] = validate_public_key(challenge['public_key_spki_pem'])
    return result


SCRIPT = r'''
'use strict';
const CHALLENGE = __CHALLENGE_JSON__;
const OTP_IN_CHAT = __OTP_IN_CHAT__;
const form = document.getElementById('auth-form');
const output = document.getElementById('encrypted-output');
const status = document.getElementById('status');
const encryptButton = document.getElementById('encrypt-button');
const copyButton = document.getElementById('copy-button');
const fields = [...form.querySelectorAll('input')];

function decodeBase64(value) {
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}
function encodeBase64(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)));
}
function isExpired(challenge = CHALLENGE) {
  return Math.floor(Date.now() / 1000) >= challenge.expires_at;
}
function clearFields() {
  for (const field of fields) field.value = '';
}
function showExpired() {
  clearFields();
  output.value = '';
  encryptButton.disabled = true;
  copyButton.disabled = true;
  status.textContent = '有効期限が切れました。新しい認証フォームを取得してください。';
}

// AES-GCM authenticates the exact CI run, phase, nonce and expiry.
async function encryptBytes(plaintext) {
  const challenge = CHALLENGE;
  if (isExpired(challenge)) throw new Error('expired');
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const additionalData = decodeBase64(challenge.context_b64);
  try {
    const spki = decodeBase64(challenge.public_key_spki_pem
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '').replace(/\s/g, ''));
    const publicKey = await crypto.subtle.importKey('spki', spki,
      {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
    const aesKey = await crypto.subtle.importKey('raw', rawKey,
      {name: 'AES-GCM'}, false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv, additionalData, tagLength: 128}, aesKey, plaintext);
    const wrappedKey = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, publicKey, rawKey);
    if (isExpired(challenge) || CHALLENGE !== challenge) throw new Error('superseded');
    return {
      version: 1, run_id: challenge.run_id, phase: challenge.phase,
      nonce: challenge.nonce, expires_at: challenge.expires_at,
      wrapped_key: encodeBase64(wrappedKey), iv: encodeBase64(iv),
      ciphertext: encodeBase64(ciphertext)
    };
  } finally {
    rawKey.fill(0);
    plaintext.fill(0);
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (OTP_IN_CHAT && CHALLENGE.phase > 0) return;
  const challengeAtSubmit = CHALLENGE;
  output.value = '';
  copyButton.disabled = true;
  if (isExpired()) { showExpired(); return; }
  if (!window.isSecureContext || !crypto.subtle) {
    clearFields();
    status.textContent = 'このブラウザーでは暗号化を使えません。HTTPS のページを最新の Safari、Chrome または Edge で開いてください。';
    return;
  }
  let plaintext;
  if (CHALLENGE.allowed_payload === 'credentials') {
    const appleId = document.getElementById('apple-id');
    const password = document.getElementById('password');
    if (!appleId.value.trim() || appleId.value.trim().length > 254 ||
        !password.value || password.value.length > 1024) {
      status.textContent = 'Apple ID とパスワードを入力してください。';
      return;
    }
    plaintext = new TextEncoder().encode(JSON.stringify({
      apple_id: appleId.value.trim(), password: password.value
    }));
  } else {
    const code = document.getElementById('code');
    if (!/^[0-9]{6}$/.test(code.value)) {
      status.textContent = '6 桁の確認コードを入力してください。';
      return;
    }
    plaintext = new TextEncoder().encode(JSON.stringify({code: code.value}));
  }
  clearFields();
  encryptButton.disabled = true;
  status.textContent = '端末内で暗号化しています…';
  try {
    const envelope = await encryptBytes(plaintext);
    output.value = JSON.stringify(envelope);
    copyButton.disabled = false;
    status.textContent = '暗号化しました。下の暗号化 JSON だけをコピーしてチャットに送ってください。';
  } catch {
    if (CHALLENGE !== challengeAtSubmit) return;
    if (isExpired()) { showExpired(); return; }
    status.textContent = '暗号化に失敗しました。入力欄は消去しました。ブラウザーを確認して再入力してください。';
  } finally {
    plaintext.fill(0);
    encryptButton.disabled = isExpired() || (OTP_IN_CHAT && CHALLENGE.phase > 0);
  }
});

copyButton.addEventListener('click', async () => {
  if (isExpired()) { showExpired(); return; }
  if (!output.value) return;
  try {
    await navigator.clipboard.writeText(output.value);
    status.textContent = '暗号化 JSON をコピーしました。チャットに貼り付けて送ってください。';
  } catch {
    // iOS Safari may deny clipboard access; only the encrypted JSON is selected.
    try {
      output.focus();
      output.select();
      output.setSelectionRange(0, output.value.length);
    } catch {}
    status.textContent = '暗号化 JSON を選択しました。手動でコピーしてチャットに送ってください。';
  }
});
window.addEventListener('pagehide', () => {
  clearFields();
  output.value = '';
});
if (isExpired()) showExpired();
setInterval(() => { if (isExpired()) showExpired(); }, 1000);
'''


LIVE_SCRIPT = r'''
// This URL is generated from the fixed CI run. No input values enter requests.
const LIVE_RUN_ID = __LIVE_RUN_JSON__;
const PUBLIC_CHALLENGE_URL = 'https://raw.githubusercontent.com/444yttt/Y3POSClient/' +
  'bereal-auth-challenges-' + LIVE_RUN_ID + '/ci-auth-challenge/current.json';
const PUBLIC_FIELDS = ['version', 'purpose', 'run_id', 'phase', 'nonce', 'expires_at',
  'public_key_spki_pem', 'context_b64', 'allowed_payload'].sort();
let refreshing = false;

// The challenge is a flat object of strings and unsigned integer tokens.
// Parse that narrow JSON grammar so duplicate fields cannot be silently accepted.
function parsePublicChallenge(text) {
  if (new TextEncoder().encode(text).length > 16384) throw new Error('size');
  let position = 0;
  const result = Object.create(null);
  function whitespace() { while (/[\t\r\n ]/.test(text[position] || 'x')) position++; }
  function character(expected) {
    whitespace();
    if (text[position++] !== expected) throw new Error('json');
  }
  function string() {
    whitespace();
    const expression = /"(?:[^"\\\u0000-\u001f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"/y;
    expression.lastIndex = position;
    const match = expression.exec(text);
    if (!match) throw new Error('json');
    position = expression.lastIndex;
    return JSON.parse(match[0]);
  }
  character('{');
  whitespace();
  if (text[position] === '}') throw new Error('fields');
  while (true) {
    const key = string();
    if (Object.prototype.hasOwnProperty.call(result, key)) throw new Error('duplicate');
    character(':');
    whitespace();
    if (text[position] === '"') result[key] = string();
    else {
      const expression = /(?:0|[1-9][0-9]*)/y;
      expression.lastIndex = position;
      const match = expression.exec(text);
      if (!match) throw new Error('json');
      position = expression.lastIndex;
      result[key] = Number(match[0]);
    }
    whitespace();
    if (text[position] === '}') { position++; break; }
    character(',');
  }
  whitespace();
  if (position !== text.length) throw new Error('json');
  return result;
}

async function validatePublicChallenge(candidate) {
  if (Object.keys(candidate).sort().join('|') !== PUBLIC_FIELDS.join('|') ||
      candidate.version !== 1 || candidate.purpose !== 'bereal-apple-auth' ||
      typeof candidate.run_id !== 'string' || candidate.run_id !== LIVE_RUN_ID ||
      !Number.isInteger(candidate.phase) || candidate.phase < 0 || candidate.phase > 3 ||
      typeof candidate.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(candidate.nonce) ||
      !Number.isSafeInteger(candidate.expires_at) || isExpired(candidate) ||
      candidate.expires_at - Math.floor(Date.now() / 1000) > (candidate.phase === 0 ? 2400 : 600) ||
      candidate.allowed_payload !== (candidate.phase === 0 ? 'credentials' : 'two_factor')) {
    throw new Error('challenge');
  }
  const expectedContext = 'BeReal493AppleAuthRelayV1|' + candidate.run_id + '|' +
    candidate.phase + '|' + candidate.nonce + '|' + candidate.expires_at;
  if (candidate.context_b64 !== encodeBase64(new TextEncoder().encode(expectedContext))) {
    throw new Error('context');
  }
  if (typeof candidate.public_key_spki_pem !== 'string' || candidate.public_key_spki_pem.length > 2048) {
    throw new Error('key');
  }
  const pem = candidate.public_key_spki_pem.replace(/\r\n/g, '\n');
  const match = /^-----BEGIN PUBLIC KEY-----\n((?:[A-Za-z0-9+/=]{1,64}\n)+)-----END PUBLIC KEY-----\n?$/.exec(pem);
  if (!match) throw new Error('key');
  const body = match[1].replace(/\n/g, '');
  const spki = decodeBase64(body);
  if (encodeBase64(spki) !== body) throw new Error('key');
  const key = await crypto.subtle.importKey('spki', spki,
    {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
  if (key.algorithm.modulusLength < 2048 || key.algorithm.modulusLength > 4096 ||
      encodeBase64(key.algorithm.publicExponent) !== 'AQAB') throw new Error('key');
  return {...candidate, public_key_spki_pem: pem};
}

function applyPublicChallenge(candidate) {
  if (candidate.phase < CHALLENGE.phase) throw new Error('regression');
  if (candidate.phase === CHALLENGE.phase && candidate.nonce === CHALLENGE.nonce) {
    for (const key of PUBLIC_FIELDS) if (candidate[key] !== CHALLENGE[key]) throw new Error('mutation');
    return;
  }
  if (candidate.phase === CHALLENGE.phase && candidate.expires_at <= CHALLENGE.expires_at) {
    throw new Error('stale');
  }
  clearFields();
  output.value = '';
  copyButton.disabled = true;
  CHALLENGE = candidate;
  document.getElementById('auth-fields').innerHTML = OTP_IN_CHAT && candidate.phase > 0 ? '' : candidate.phase === 0 ?
    '<label for="apple-id">Apple ID</label>' +
    '<input id="apple-id" type="text" maxlength="254" required autocomplete="off" autocapitalize="none" spellcheck="false">' +
    '<label for="password">パスワード</label>' +
    '<input id="password" type="password" maxlength="1024" required autocomplete="off" autocapitalize="none" spellcheck="false">' :
    '<label for="code">6 桁の確認コード</label>' +
    '<input id="code" type="text" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required autocomplete="off" autocapitalize="none" spellcheck="false">';
  fields = [...form.querySelectorAll('input')];
  form.hidden = OTP_IN_CHAT && candidate.phase > 0;
  document.getElementById('encrypted-output-panel').hidden = form.hidden;
  document.getElementById('phase-display').textContent = String(candidate.phase);
  document.getElementById('expiry-display').textContent =
    new Date(candidate.expires_at * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  document.getElementById('phase-instruction').textContent = OTP_IN_CHAT && candidate.phase > 0 ?
    'SMSの6桁確認コードを、このチャットにそのまま送ってください' : candidate.phase === 0 ?
    'Apple ID とパスワードを入力してください。' :
    'Apple の信頼済み端末または電話番号に届いた 6 桁の確認コードを入力してください。このページが自動で切り替わっています。';
  encryptButton.disabled = form.hidden;
  status.textContent = OTP_IN_CHAT && candidate.phase > 0 ?
    'SMSの6桁確認コードを、このチャットにそのまま送ってください' : candidate.phase === 0 ? '認証情報を入力してください。' :
    '確認コードの入力に切り替わりました。6 桁のコードを暗号化し、暗号化 JSON をチャットに送ってください。';
}

async function refreshPublicChallenge() {
  if (refreshing || !window.isSecureContext || !crypto.subtle) return;
  refreshing = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const url = PUBLIC_CHALLENGE_URL + '?refresh=' + Date.now();
    const response = await fetch(url, {
      method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store',
      redirect: 'error', referrerPolicy: 'no-referrer', headers: {'Accept': 'application/json'},
      signal: controller.signal
    });
    if (!response.ok || response.url !== url) throw new Error('response');
    const candidate = await validatePublicChallenge(parsePublicChallenge(await response.text()));
    applyPublicChallenge(candidate);
  } catch {
    // Keep valid current inputs unchanged when public refresh is unavailable.
    // Expired inputs are independently cleared by the one-second expiry timer.
  } finally {
    clearTimeout(timeout);
    refreshing = false;
  }
}
refreshPublicChallenge();
setInterval(refreshPublicChallenge, 3000);
'''


HTML = '''<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src '__SCRIPT_HASH__'; style-src '__STYLE_HASH__'; connect-src 'none'; img-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'">
  <title>BeReal IPA 署名用の Apple 認証</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0; padding: 24px; line-height: 1.65; }
    main { max-width: 700px; margin: 0 auto; }
    h1 { font-size: 1.5rem; }
    label { display: block; margin-top: 20px; font-weight: 600; }
    input, textarea, button { font: inherit; font-size: 16px; box-sizing: border-box; }
    input, textarea { width: 100%; padding: 10px; margin-top: 6px; }
    textarea { min-height: 150px; word-break: break-all; }
    input, button { min-height: 44px; }
    button { padding: 10px 16px; margin-top: 16px; cursor: pointer; }
    button:disabled { cursor: default; }
    .details { font-size: .9rem; }
    #status { min-height: 3.3em; }
  </style>
</head>
<body>
<main>
  <h1>BeReal IPA 署名用の Apple 認証</h1>
  <p id="phase-instruction">__PHASE_INSTRUCTION__</p>
  <p>入力は端末内で暗号化されます。このページは入力内容を通信・保存しません。実行中の Y3POSClient CI だけが復号し、使用後は CI の一時データを破棄します。</p>
  __LIVE_NOTICE__
  <p><strong>__PRIVATE_INPUT_NOTICE__</strong></p>
  <p class="details">対象 CI 実行: __RUN_ID__ / 認証段階: <span id="phase-display">__PHASE__</span><br>有効期限: <time id="expiry-display">__EXPIRY__ UTC</time></p>
  <form id="auth-form" autocomplete="off"__FORM_HIDDEN__>
    <div id="auth-fields">__FIELDS__</div>
    <button id="encrypt-button" type="submit">端末内で暗号化</button>
  </form>
  <p id="status" role="status" aria-live="polite">__INITIAL_STATUS__</p>
  <div id="encrypted-output-panel"__FORM_HIDDEN__>
  <label for="encrypted-output">チャットに送る暗号化 JSON</label>
  <textarea id="encrypted-output" readonly spellcheck="false" autocomplete="off" aria-describedby="status"></textarea>
  <button id="copy-button" type="button" disabled>暗号化 JSON をコピー</button>
  </div>
  <noscript><p>JavaScript が無効のため暗号化できません。このフォームに認証情報を入力しないでください。</p></noscript>
</main>
<script>
__SCRIPT__
</script>
</body>
</html>
'''


def render_html(challenge, now=None, *, live_challenge=False, otp_in_chat=False):
    if otp_in_chat and not live_challenge:
        raise ValueError('OTP in chat requires live challenge mode')
    challenge = validate_challenge(challenge, now)
    if challenge['allowed_payload'] == 'credentials':
        instruction = 'このページを Safari などのブラウザーで開き、Apple ID とパスワードを入力してください。'
        fields = '''<label for="apple-id">Apple ID</label>
    <input id="apple-id" type="text" maxlength="254" required autocomplete="off" autocapitalize="none" spellcheck="false">
    <label for="password">パスワード</label>
    <input id="password" type="password" maxlength="1024" required autocomplete="off" autocapitalize="none" spellcheck="false">'''
    else:
        instruction = 'Apple の信頼済み端末または電話番号に届いた 6 桁の確認コードを入力してください。'
        fields = '''<label for="code">6 桁の確認コード</label>
    <input id="code" type="text" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required autocomplete="off" autocapitalize="none" spellcheck="false">'''
    safe_json = json.dumps(challenge, ensure_ascii=True, separators=(',', ':'))
    safe_json = safe_json.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    script = SCRIPT.replace('__CHALLENGE_JSON__', safe_json)
    script = script.replace('__OTP_IN_CHAT__', 'true' if otp_in_chat else 'false')
    if live_challenge:
        script = script.replace('const CHALLENGE = ', 'let CHALLENGE = ', 1)
        script = script.replace('const fields = ', 'let fields = ', 1)
        script += LIVE_SCRIPT.replace('__LIVE_RUN_JSON__', json.dumps(challenge['run_id']))
    expiry = datetime.fromtimestamp(challenge['expires_at'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    sms_mode = otp_in_chat and challenge['phase'] > 0
    if sms_mode:
        instruction = 'SMSの6桁確認コードを、このチャットにそのまま送ってください'
        fields = ''
    replacements = {
        '__PHASE_INSTRUCTION__': instruction, '__RUN_ID__': challenge['run_id'],
        '__PHASE__': str(challenge['phase']), '__EXPIRY__': expiry, '__FIELDS__': fields,
        '__SCRIPT__': script,
        '__PRIVATE_INPUT_NOTICE__': 'Apple ID・パスワードをチャットに直接送らないでください。認証情報は下で暗号化して送ってください。' if otp_in_chat else 'Apple ID・パスワード・確認コードをチャットに直接送らないでください。下に生成される暗号化 JSON だけを送ってください。',
        '__FORM_HIDDEN__': ' hidden' if sms_mode else '',
        '__INITIAL_STATUS__': instruction if sms_mode else '入力後、「端末内で暗号化」を押してください。',
        '__LIVE_NOTICE__': ('<p class="details">認証が進むと、SMS の確認コードをチャットに送る案内へ自動で切り替わります。このページを開いたままお待ちください。公開の認証段階だけを 3 秒ごとに確認します。</p>' if otp_in_chat else '<p class="details">確認コードの入力欄は自動で切り替わります。このページを開いたままお待ちください。公開の認証段階だけを 3 秒ごとに確認します。</p>') if live_challenge else '',
    }
    html = HTML
    for token, value in replacements.items():
        html = html.replace(token, value)
    if live_challenge:
        html = html.replace("connect-src 'none'", 'connect-src https://raw.githubusercontent.com')
    # Hash the exact inline element contents, including their surrounding LF.
    # This permits only this challenge's authored code and styles on static HTTPS.
    for element, token in [('script', '__SCRIPT_HASH__'), ('style', '__STYLE_HASH__')]:
        contents = re.search(rf'<{element}>(.*?)</{element}>', html, re.DOTALL).group(1)
        digest = base64.b64encode(hashlib.sha256(contents.encode('utf-8')).digest()).decode('ascii')
        html = html.replace(token, 'sha256-' + digest)
    return html


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate challenge field')
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('challenge', type=Path, help='Public CI challenge JSON only')
    parser.add_argument('--output', type=Path, required=True, help='Standalone static HTML output')
    parser.add_argument('--live-challenge', action='store_true',
                        help='Refresh only the fixed CI run public challenge from GitHub')
    parser.add_argument('--otp-in-chat', action='store_true',
                        help='With live mode, request SMS OTP directly in chat instead of an input field')
    args = parser.parse_args(argv)
    raw = args.challenge.read_bytes()
    if len(raw) > MAX_CHALLENGE_BYTES:
        raise ValueError('Challenge JSON is too large')
    challenge = json.loads(raw, object_pairs_hook=_unique_object)
    html = render_html(challenge, live_challenge=args.live_challenge, otp_in_chat=args.otp_in_chat)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding='utf-8')
    print('Created static client-side Apple authentication form from the public CI challenge.')


if __name__ == '__main__':
    main()
