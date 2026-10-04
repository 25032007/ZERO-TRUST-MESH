import assert from 'node:assert/strict';
import { test } from 'node:test';
import { base32Decode, base32Encode, generateTotp, hotp, verifyTotp } from '../src/crypto/totp.js';

// RFC 4226 Appendix D test vectors: secret "12345678901234567890", counters 0..9.
const RFC4226 = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

test('HOTP matches the RFC 4226 test vectors', () => {
  const secret = Buffer.from('12345678901234567890');
  RFC4226.forEach((expected, counter) => assert.equal(hotp(secret, counter), expected));
});

test('TOTP matches the RFC 6238 vector for T=59s (6-digit truncation of 94287082)', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(generateTotp(secret, 59_000), '287082');
});

test('base32 round-trips arbitrary bytes', () => {
  const bytes = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255, 17, 99]);
  assert.deepEqual(base32Decode(base32Encode(bytes)), bytes);
});

test('verifyTotp accepts the current code and ±1 step, rejects further drift', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  const now = 1_700_000_000_000;
  const code = generateTotp(secret, now);
  assert.notEqual(verifyTotp(secret, code, now), null);
  assert.notEqual(verifyTotp(secret, code, now + 30_000), null); // one step later
  assert.equal(verifyTotp(secret, code, now + 120_000), null); // four steps later
});

test('verifyTotp rejects malformed input', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  for (const bad of ['', '12345', '1234567', 'abcdef', '12 456']) assert.equal(verifyTotp(secret, bad, 0), null);
});
