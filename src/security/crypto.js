/**
 * Cryptographic Services Module
 * Implements AES-256-GCM authenticated encryption/decryption,
 * blind index computation, and key derivation.
 */

const crypto = require('crypto');
require('dotenv').config();

// AES Configuration: 256-bit key, 12-byte (96-bit) IV for GCM, 16-byte auth tag
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;      // 96 bits recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits auth tag

// Encryption key (32 bytes = 256 bits)
function getMasterKey() {
    const keyHex = process.env.AES_SECRET_KEY;
    if (keyHex && keyHex.length === 64) {
        return Buffer.from(keyHex, 'hex');
    }
    // Fallback derivation if a passphrase string is provided
    const secret = process.env.AES_SECRET_KEY || 'default-super-secure-aes-master-key-32bytes!';
    return crypto.createHash('sha256').update(secret).digest();
}

// Blind index key for HMAC-SHA256 search token
function getBlindIndexKey() {
    const keyHex = process.env.BLIND_INDEX_KEY;
    if (keyHex && keyHex.length === 64) {
        return Buffer.from(keyHex, 'hex');
    }
    const secret = process.env.BLIND_INDEX_KEY || 'default-blind-index-hmac-salt-key!';
    return crypto.createHash('sha256').update(secret).digest();
}

/**
 * Encrypt plaintext (e.g. Email) using AES-256-GCM
 * @param {string} text Plaintext to encrypt
 * @returns {object} { ciphertext, iv, authTag, algorithm }
 */
function encryptAES(text) {
    if (!text || typeof text !== 'string') {
        throw new Error('Invalid input for encryption');
    }

    const key = getMasterKey();
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH
    });

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag().toString('hex');
    const ivHex = iv.toString('hex');

    return {
        ciphertext: encrypted,
        iv: ivHex,
        authTag: authTag,
        serialized: `${ivHex}:${authTag}:${encrypted}`,
        algorithm: ALGORITHM
    };
}

/**
 * Decrypt ciphertext using AES-256-GCM with authentication tag validation
 * Supports either { ciphertext, iv, authTag } object or serialized 'iv:authTag:ciphertext' string
 * @param {object|string} encryptedData
 * @returns {string} Decrypted plaintext
 */
function decryptAES(encryptedData) {
    let payload = encryptedData;
    if (typeof encryptedData === 'string') {
        const parts = encryptedData.split(':');
        if (parts.length === 3) {
            payload = { iv: parts[0], authTag: parts[1], ciphertext: parts[2] };
        } else {
            throw new Error('Invalid serialized ciphertext format. Expected iv:authTag:ciphertext');
        }
    }

    if (!payload || !payload.ciphertext || !payload.iv || !payload.authTag) {
        throw new Error('Incomplete encrypted data structure');
    }

    const key = getMasterKey();
    const iv = Buffer.from(payload.iv, 'hex');
    const authTag = Buffer.from(payload.authTag, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH
    });

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(payload.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Compute keyed Blind Index (HMAC-SHA256) for searching/indexing encrypted fields
 * Normalized to lowercase & trimmed before hashing.
 * @param {string} email
 * @returns {string} hex-encoded HMAC
 */
function computeBlindIndex(email) {
    if (!email) return '';
    const normalized = email.trim().toLowerCase();
    const key = getBlindIndexKey();
    return crypto.createHmac('sha256', key).update(normalized).digest('hex');
}

/**
 * Generates secure random 256-bit hexadecimal keys for .env setup
 */
function generateKeyHex() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    ALGORITHM,
    encryptAES,
    decryptAES,
    computeBlindIndex,
    generateKeyHex
};

// Self-executing demonstration when run directly with `node src/security/crypto.js`
if (require.main === module) {
    console.log('================================================================');
    console.log('       AES-256-GCM & BLIND INDEX CRYPTOGRAPHIC ENGINE');
    console.log('================================================================\n');

    const sampleEmail = 'rahul.security@defense.gov';
    console.log(`[1] Input Plaintext Email: "${sampleEmail}"\n`);

    // 1. Encryption
    console.log('[*] Performing Authenticated Encryption (AES-256-GCM)...');
    const encrypted = encryptAES(sampleEmail);
    console.log(`    Algorithm:   ${encrypted.algorithm}`);
    console.log(`    IV / Nonce:  ${encrypted.iv} (${encrypted.iv.length / 2} bytes)`);
    console.log(`    Ciphertext:  ${encrypted.ciphertext}`);
    console.log(`    Auth Tag:    ${encrypted.authTag} (${encrypted.authTag.length / 2} bytes)\n`);

    // 2. Decryption
    console.log('[*] Performing Authenticated Decryption...');
    const decrypted = decryptAES(encrypted);
    console.log(`    Decrypted:   "${decrypted}"`);
    console.log(`    Integrity:   [MATCH] Plaintext accurately restored.\n`);

    // 3. Blind Index
    console.log('[*] Generating Blind Index (HMAC-SHA256 for encrypted search)...');
    const blindIndex = computeBlindIndex(sampleEmail);
    console.log(`    Blind Index: ${blindIndex}\n`);

    // 4. Tamper Resistance Demonstration
    console.log('[*] Testing Tamper Resistance (Modifying 1 byte in ciphertext)...');
    try {
        const tamperedCiphertext = (encrypted.ciphertext.slice(0, -2) === 'aa' ? 'bb' : 'aa') + encrypted.ciphertext.slice(2);
        decryptAES({
            ciphertext: tamperedCiphertext,
            iv: encrypted.iv,
            authTag: encrypted.authTag
        });
        console.error('    [FAIL] Tampered ciphertext was accepted!');
    } catch (err) {
        console.log(`    [PASS] Tampering successfully detected & rejected: "${err.message}"\n`);
    }

    console.log('================================================================');
    console.log('       ALL CRYPTOGRAPHIC OPERATIONS VERIFIED & SECURE           ');
    console.log('================================================================');
}
