const assert = require('assert');
const { encryptAES, decryptAES, computeBlindIndex } = require('../src/security/crypto');
const { validateEmail, validatePassword, hashPassword, verifyPassword } = require('../src/security/auth');
const userRepo = require('../src/data/userRepo');

async function runSecurityTests() {
  console.log('====================================================');
  console.log('   RUNNING CRYPTOGRAPHIC & SECURITY SUITE TESTS');
  console.log('====================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (e) {
      console.error(`[FAIL] ${name}: ${e.message}`);
    }
  }

  async function testAsync(name, fn) {
    total++;
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (e) {
      console.error(`[FAIL] ${name}: ${e.message}`);
    }
  }

  // 1. Email RFC 5322 Validation Tests
  test('Email Validator: Valid Emails', () => {
    assert.strictEqual(validateEmail('alice@example.com').valid, true);
    assert.strictEqual(validateEmail('user.name+tag@sub.domain.co.uk').valid, true);
    assert.strictEqual(validateEmail('security_team@enterprise.org').valid, true);
  });

  test('Email Validator: Invalid Emails Rejected', () => {
    assert.strictEqual(validateEmail('plainaddress').valid, false);
    assert.strictEqual(validateEmail('@missingusername.com').valid, false);
    assert.strictEqual(validateEmail('username@.com').valid, false);
    assert.strictEqual(validateEmail('username@domain').valid, false);
    assert.strictEqual(validateEmail('user..name@domain.com').valid, false);
    assert.strictEqual(validateEmail('').valid, false);
  });

  // 2. Password Strength Policy Tests
  test('Password Validator: Enforces Complexity Rules', () => {
    assert.strictEqual(validatePassword('Weak1!').valid, false); // < 8 chars
    assert.strictEqual(validatePassword('alllowercasewith123!').valid, false); // missing uppercase
    assert.strictEqual(validatePassword('ALLUPPERWITH123!').valid, false); // missing lowercase
    assert.strictEqual(validatePassword('NoSpecialChar1234').valid, false); // missing special char
    assert.strictEqual(validatePassword('NoNumbersHere!@#$').valid, false); // missing number
    assert.strictEqual(validatePassword('Valid#Enterprise$2026!').valid, true);
  });

  // 3. AES-256-GCM Encryption & Decryption Tests
  test('AES-256-GCM: Encrypts and Decrypts accurately', () => {
    const originalEmail = 'analyst.charlie@defense.gov';
    const enc = encryptAES(originalEmail);
    assert.strictEqual(typeof enc.serialized, 'string');
    assert.strictEqual(enc.iv.length, 24); // 12 bytes = 24 hex chars
    assert.strictEqual(enc.authTag.length, 32); // 16 bytes = 32 hex chars

    const decrypted = decryptAES(enc.serialized);
    assert.strictEqual(decrypted, originalEmail);
  });

  test('AES-256-GCM: Fresh Nonce / IV per Encryption (No IV reuse)', () => {
    const originalEmail = 'same.email@enterprise.org';
    const enc1 = encryptAES(originalEmail);
    const enc2 = encryptAES(originalEmail);

    assert.notStrictEqual(enc1.iv, enc2.iv, 'IVs must be uniquely generated');
    assert.notStrictEqual(enc1.ciphertext, enc2.ciphertext, 'Ciphertexts must differ due to unique IV');
    assert.strictEqual(decryptAES(enc1.serialized), originalEmail);
    assert.strictEqual(decryptAES(enc2.serialized), originalEmail);
  });

  test('AES-256-GCM: Tamper Detection (Integrity Guarantee)', () => {
    const enc = encryptAES('critical.data@org.com');
    // Modify one byte of ciphertext
    const parts = enc.serialized.split(':');
    const tamperedCipher = parts[2].substring(0, parts[2].length - 2) + 'ff';
    const tamperedSerialized = `${parts[0]}:${parts[1]}:${tamperedCipher}`;

    assert.throws(() => {
      decryptAES(tamperedSerialized);
    }, /Unsupported state or unable to authenticate data|integrity/, 'Tampered ciphertext must be rejected');
  });

  // 4. Blind Index Consistency Tests
  test('Blind Index: Deterministic and Case-Insensitive', () => {
    const hmac1 = computeBlindIndex('Alice.Smith@Domain.COM');
    const hmac2 = computeBlindIndex('alice.smith@domain.com');
    const hmacOther = computeBlindIndex('bob.jones@domain.com');

    assert.strictEqual(hmac1, hmac2);
    assert.notStrictEqual(hmac1, hmacOther);
    assert.strictEqual(hmac1.length, 64); // 256 bits = 64 hex chars
  });

  // 5. Bcrypt Password Hashing Tests
  await testAsync('Bcrypt: Generates Secure Salted Hashes & Verifies', async () => {
    const plain = 'SecretMasterKey#2026!';
    const hash = await hashPassword(plain);

    assert.strictEqual(hash.startsWith('$2a$12$') || hash.startsWith('$2b$12$'), true, 'Must use bcrypt 12 rounds ($2a$ or $2b$)');
    
    // Verification
    const isMatch = await verifyPassword(plain, hash);
    const isWrong = await verifyPassword('WrongPassword123!', hash);

    assert.strictEqual(isMatch, true);
    assert.strictEqual(isWrong, false);
  });

  // 6. Database Storage Verification (Zero Plaintext Stored)
  await testAsync('Database Audit: Confirms Zero Plaintext Stored', async () => {
    userRepo.initDb();

    const plainEmail = `auditor.${Date.now()}@cyber.mil`;
    const plainPass = 'Auditor@2026$Pass!';

    const registered = await userRepo.registerUser({
      fullName: 'Auditor Eve',
      email: plainEmail,
      password: plainPass
    });

    assert.ok(registered.id, 'User ID must be returned');
    const records = userRepo.getStorageInspection();
    const storedUser = records.find(u => u.id === registered.id);
    assert.ok(storedUser, 'User record must be present in storage');
    assert.strictEqual(storedUser.encryptedEmail.ciphertext.includes(plainEmail), false);
    
    // Assert that the raw database inspection contains NO plaintext email or pass
    const rawDisk = JSON.stringify(records);
    assert.strictEqual(rawDisk.includes(plainEmail), false, 'Plaintext email must NOT exist on disk');
    assert.strictEqual(rawDisk.includes(plainPass), false, 'Plaintext password must NOT exist on disk');
  });

  console.log(`\n====================================================`);
  console.log(` RESULTS: ${passed} / ${total} Tests Passed Successfully!`);
  console.log('====================================================');
}

runSecurityTests().catch(console.error);
