"""Offline form protocol and actual browser WebCrypto interoperability checks."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


SPEC = importlib.util.spec_from_file_location(
    'apple_auth_form', Path(__file__).parents[1] / 'scripts' / 'create_apple_auth_form.py')
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


NODE_BROWSER = r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto, privateDecrypt, constants} from 'node:crypto';

const [htmlPath, keyPath, mode] = process.argv.slice(1);
const html = fs.readFileSync(htmlPath, 'utf8');
const script = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/)[1];
const challenge = JSON.parse(script.match(/const CHALLENGE = (.*);/)[1]);
const callbacks = {};
const elements = {};
const idNames = ['encrypted-output', 'status', 'encrypt-button', 'copy-button',
                 ...(challenge.phase === 0 ? ['apple-id', 'password'] : ['code'])];
for (const name of idNames) elements[name] = {value: '', textContent: '', disabled: false,
                                          focus() {}, select() {}};
const inputs = idNames.filter(name => ['apple-id', 'password', 'code'].includes(name))
                     .map(name => elements[name]);
elements['auth-form'] = {
  querySelectorAll() { return inputs; },
  addEventListener(name, callback) { callbacks['form-' + name] = callback; }
};
elements['copy-button'].addEventListener = (name, callback) => {
  callbacks['copy-' + name] = callback;
};
let now = mode === 'expired' ? challenge.expires_at * 1000 : Date.now();
class Clock extends Date { static now() { return now; } }
const context = {
  document: {getElementById(name) { assert.ok(elements[name]); return elements[name]; }},
  window: {isSecureContext: mode !== 'insecure', addEventListener(name, callback) {
    callbacks['window-' + name] = callback;
  }},
  crypto: webcrypto, TextEncoder, Uint8Array, Date: Clock,
  atob(value) { return Buffer.from(value, 'base64').toString('binary'); },
  btoa(value) { return Buffer.from(value, 'binary').toString('base64'); },
  navigator: {clipboard: {async writeText(value) { context.copied = value; }}},
  setInterval(callback) { callbacks.timer = callback; }
};
vm.runInNewContext(script, context, {timeout: 1000});
const appleId = 'local-roundtrip@example.invalid';
const password = 'local-test-only-&<secret>\\"';
const code = '123456';
function populate() {
  if (challenge.phase === 0) {
    elements['apple-id'].value = appleId;
    elements.password.value = password;
  } else elements.code.value = mode === 'bad-code' ? '12345x' : code;
}
populate();
await callbacks['form-submit']({preventDefault() {}});
if (['expired', 'insecure', 'bad-code'].includes(mode)) {
  assert.equal(elements['encrypted-output'].value, '');
  assert.equal(elements['copy-button'].disabled, true);
  if (mode !== 'bad-code') assert.ok(inputs.every(input => input.value === ''));
  if (mode === 'expired') assert.equal(elements['encrypt-button'].disabled, true);
  console.log(JSON.stringify({rejected: true, outputEmpty: true}));
} else {
  const serialized = elements['encrypted-output'].value;
  assert.ok(inputs.every(input => input.value === ''));
  assert.equal(elements['copy-button'].disabled, false);
  for (const secret of [appleId, password, code]) assert.ok(!serialized.includes(secret));
  const envelope = JSON.parse(serialized);
  assert.deepEqual(Object.keys(envelope).sort(), [
    'version', 'run_id', 'phase', 'nonce', 'expires_at', 'wrapped_key', 'iv', 'ciphertext'
  ].sort());
  const raw = privateDecrypt({
    key: fs.readFileSync(keyPath), padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from(envelope.wrapped_key, 'base64'));
  assert.equal(raw.length, 32);
  const aes = await webcrypto.subtle.importKey('raw', raw, {name: 'AES-GCM'}, false, ['decrypt']);
  const iv = Buffer.from(envelope.iv, 'base64');
  assert.equal(iv.length, 12);
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const aad = Buffer.from(challenge.context_b64, 'base64');
  const decoded = JSON.parse(Buffer.from(await webcrypto.subtle.decrypt({
    name: 'AES-GCM', iv, additionalData: aad, tagLength: 128
  }, aes, ciphertext)).toString('utf8'));
  assert.deepEqual(decoded, challenge.phase === 0 ? {apple_id: appleId, password} : {code});
  const badAad = Buffer.from(aad); badAad[0] ^= 1;
  await assert.rejects(webcrypto.subtle.decrypt({
    name: 'AES-GCM', iv, additionalData: badAad, tagLength: 128
  }, aes, ciphertext));
  const badCipher = Buffer.from(ciphertext); badCipher[0] ^= 1;
  await assert.rejects(webcrypto.subtle.decrypt({
    name: 'AES-GCM', iv, additionalData: aad, tagLength: 128
  }, aes, badCipher));
  await callbacks['copy-click']();
  assert.equal(context.copied, serialized);
  populate();
  await callbacks['form-submit']({preventDefault() {}});
  const second = JSON.parse(elements['encrypted-output'].value);
  assert.notEqual(second.wrapped_key, envelope.wrapped_key);
  assert.notEqual(second.iv, envelope.iv);
  assert.notEqual(second.ciphertext, envelope.ciphertext);
  now = challenge.expires_at * 1000;
  callbacks.timer();
  assert.equal(elements['encrypted-output'].value, '');
  assert.equal(elements['copy-button'].disabled, true);
  assert.equal(elements['encrypt-button'].disabled, true);
  console.log(JSON.stringify({decrypted: true, tamperingRejected: true,
                             freshKeys: true, fieldsCleared: true, expiryCleared: true}));
}
'''


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed for ephemeral public test keys')
class AppleAuthFormTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.private = cls.root / 'test-only-private.pem'
        cls.public = cls.root / 'test-only-public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                        '-out', str(cls.private)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.private), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)
        cls.pem = cls.public.read_text()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def challenge(self, phase=0, now=None):
        now = int(time.time()) if now is None else now
        expiry = now + (1200 if phase == 0 else 300)
        run_id = '38436216798'
        nonce = 'ab' * 32
        context = f'BeReal493AppleAuthRelayV1|{run_id}|{phase}|{nonce}|{expiry}'
        return {'version': 1, 'purpose': 'bereal-apple-auth', 'run_id': run_id,
                'phase': phase, 'nonce': nonce, 'expires_at': expiry,
                'public_key_spki_pem': self.pem,
                'context_b64': base64.b64encode(context.encode()).decode(),
                'allowed_payload': 'credentials' if phase == 0 else 'two_factor'}

    def test_rejects_expiry_scope_type_and_context_changes(self):
        now = 1700000000
        original = self.challenge(now=now)
        invalid = [
            {'version': True}, {'version': 2}, {'purpose': 'other'},
            {'run_id': '38436216798<script>'}, {'run_id': '0'}, {'run_id': 123},
            {'phase': True}, {'phase': -1}, {'phase': 4}, {'allowed_payload': 'two_factor'},
            {'nonce': 'ab' * 31}, {'nonce': 'AB' * 32}, {'expires_at': now},
            {'expires_at': now + 2401}, {'expires_at': float(now + 1200)},
            {'expires_at': True}, {'context_b64': original['context_b64'] + '\n'},
            {'context_b64': base64.b64encode(b'other run').decode()}, {'private_key': 'unexpected'},
        ]
        for change in invalid:
            with self.subTest(field=next(iter(change))), self.assertRaises(ValueError):
                generator.validate_challenge({**original, **change}, now=now)
        otp = self.challenge(phase=1, now=now)
        otp['expires_at'] = now + 601
        with self.assertRaises(ValueError): generator.validate_challenge(otp, now=now)
        self.assertEqual(generator.validate_challenge(original, now=now), original)

    def test_rejects_private_nonrsa_undersized_and_trailing_public_key_data(self):
        invalid = [self.private.read_text(), self.pem + '\nextra',
                   self.pem.replace('BEGIN PUBLIC KEY', 'BEGIN RSA PUBLIC KEY'),
                   '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n']
        for algorithm, options in [('RSA', ['-pkeyopt', 'rsa_keygen_bits:1024']),
                                   ('EC', ['-pkeyopt', 'ec_paramgen_curve:P-256'])]:
            private = self.root / (algorithm + '.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', algorithm, *options, '-out', str(private)],
                           check=True, capture_output=True)
            result = subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout'],
                                    check=True, capture_output=True)
            invalid.append(result.stdout.decode())
        for pem in invalid:
            with self.subTest(header=pem.splitlines()[0]), self.assertRaises(ValueError):
                generator.validate_public_key(pem)
        self.assertEqual(generator.validate_public_key(self.pem), self.pem)

    def test_credentials_and_otp_html_show_only_their_scoped_fields_and_no_network_or_storage(self):
        credentials = generator.render_html(self.challenge())
        otp = generator.render_html(self.challenge(phase=1))
        self.assertIn('id="apple-id"', credentials)
        self.assertIn('id="password" type="password"', credentials)
        self.assertNotIn('id="code"', credentials)
        self.assertIn('id="code"', otp)
        self.assertNotIn('id="password"', otp)
        self.assertNotIn('id="apple-id"', otp)
        for html in (credentials, otp):
            self.assertIn('connect-src \'none\'', html)
            self.assertIn('form-action \'none\'', html)
            self.assertIn('aria-live="polite"', html)
            self.assertIn(' UTC</time>', html)
            for prohibited in ('fetch(', 'XMLHttpRequest', 'sendBeacon', 'localStorage',
                               'sessionStorage', 'document.cookie', 'console.', 'http://', 'https://'):
                self.assertNotIn(prohibited, html)
            self.assertNotIn('PRIVATE KEY', html)

    def test_cli_does_not_accept_duplicate_fields_or_oversized_input(self):
        challenge = self.root / 'challenge.json'
        output = self.root / 'generated.html'
        raw = json.dumps(self.challenge())
        challenge.write_text('{"version":1,' + raw[1:])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            generator.main([str(challenge), '--output', str(output)])
        challenge.write_bytes(b' ' * (generator.MAX_CHALLENGE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'too large'):
            generator.main([str(challenge), '--output', str(output)])
        self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which('node'), 'Node WebCrypto is needed for browser interoperability')
    def test_webcrypto_rsa_aes_round_trip_both_phases_and_rejects_tampering(self):
        for phase in (0, 1):
            with self.subTest(phase=phase):
                html = self.root / f'phase-{phase}.html'
                html.write_text(generator.render_html(self.challenge(phase=phase)))
                result = subprocess.run(['node', '--input-type=module', '-e', NODE_BROWSER,
                                         str(html), str(self.private), 'roundtrip'],
                                        check=True, capture_output=True, text=True, timeout=15)
                checks = json.loads(result.stdout)
                self.assertTrue(all(checks.values()))
                self.assertEqual(set(checks), {'decrypted', 'tamperingRejected', 'freshKeys',
                                              'fieldsCleared', 'expiryCleared'})

    @unittest.skipUnless(shutil.which('node'), 'Node WebCrypto is needed for browser validation')
    def test_browser_rejects_expired_insecure_and_invalid_otp_before_output(self):
        for mode, phase in [('expired', 0), ('insecure', 0), ('bad-code', 1)]:
            with self.subTest(mode=mode):
                html = self.root / f'{mode}.html'
                html.write_text(generator.render_html(self.challenge(phase=phase)))
                result = subprocess.run(['node', '--input-type=module', '-e', NODE_BROWSER,
                                         str(html), str(self.private), mode],
                                        check=True, capture_output=True, text=True, timeout=15)
                self.assertEqual(json.loads(result.stdout), {'rejected': True, 'outputEmpty': True})


if __name__ == '__main__':
    unittest.main()
