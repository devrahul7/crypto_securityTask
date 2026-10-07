/**
 * Authentication & Password Security Module
 * Handles password hashing (Bcrypt), email validation,
 * and JWT session generation.
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;
const JWT_SECRET = process.env.JWT_SECRET || 'jwt-fallback-secure-secret-key-64chars!';

// Standard RFC 5322 compliant email regex
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * Validate email address format and length
 * @param {string} email 
 * @returns {{ valid: boolean, error?: string }}
 */
function validateEmail(email) {
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email address is required.' };
    }
    const trimmed = email.trim();
    if (trimmed.length < 5 || trimmed.length > 254) {
        return { valid: false, error: 'Email length must be between 5 and 254 characters.' };
    }
    if (trimmed.includes('..') || !EMAIL_REGEX.test(trimmed)) {
        return { valid: false, error: 'Invalid email address format.' };
    }
    return { valid: true };
}

/**
 * Validate password complexity
 * @param {string} password 
 * @returns {{ valid: boolean, error?: string }}
 */
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: 'Password is required.' };
    }
    if (password.length < 8) {
        return { valid: false, error: 'Password must be at least 8 characters long.' };
    }
    if (password.length > 128) {
        return { valid: false, error: 'Password exceeds maximum length of 128 characters.' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, error: 'Password must include at least one uppercase letter (A-Z).' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, error: 'Password must include at least one lowercase letter (a-z).' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: 'Password must include at least one number (0-9).' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) {
        return { valid: false, error: 'Password must include at least one special character.' };
    }
    return { valid: true };
}

/**
 * Hash password securely with Bcrypt and salt
 * @param {string} password Plaintext password
 * @returns {Promise<string>} Bcrypt hash string
 */
async function hashPassword(password) {
    const validation = validatePassword(password);
    if (!validation.valid) {
        throw new Error(validation.error);
    }
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    return await bcrypt.hash(password, salt);
}

/**
 * Verify plaintext password against stored Bcrypt hash
 * Constant-time comparison
 * @param {string} password 
 * @param {string} hash 
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, hash) {
    if (!password || !hash) return false;
    return await bcrypt.compare(password, hash);
}

/**
 * Issue a signed JSON Web Token
 * @param {object} payload 
 * @param {string} expiresIn 
 * @returns {string} JWT Token
 */
function generateToken(payload, expiresIn = '2h') {
    return jwt.sign(payload, JWT_SECRET, {
        expiresIn,
        algorithm: 'HS256'
    });
}

/**
 * Verify and decode JWT
 * @param {string} token 
 * @returns {object|null}
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
        return null;
    }
}

module.exports = {
    validateEmail,
    validatePassword,
    hashPassword,
    verifyPassword,
    generateToken,
    verifyToken,
    SALT_ROUNDS
};
