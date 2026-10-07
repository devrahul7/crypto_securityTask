/**
 * User Repository & Persistent Storage
 * Enforces AES encrypted storage for emails and Bcrypt hashed storage for passwords.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { encryptAES, decryptAES, computeBlindIndex } = require('../security/crypto');
const { hashPassword, verifyPassword } = require('../security/auth');

const DB_PATH = path.join(__dirname, 'db.json');

// Ensure db.json exists
function initDb() {
    if (!fs.existsSync(DB_PATH)) {
        fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }, null, 2), 'utf8');
    }
}

function readDb() {
    initDb();
    try {
        const raw = fs.readFileSync(DB_PATH, 'utf8');
        return JSON.parse(raw);
    } catch (e) {
        return { users: [] };
    }
}

function writeDb(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Register a new user
 * - Encrypts email using AES-256-GCM
 * - Computes blind index for lookup
 * - Hashes password using Bcrypt
 */
async function registerUser({ fullName, email, password }) {
    const db = readDb();
    const normalizedEmail = email.trim().toLowerCase();
    const blindIndex = computeBlindIndex(normalizedEmail);

    // Check if user already exists via blind index
    const existing = db.users.find(u => u.emailBlindIndex === blindIndex);
    if (existing) {
        throw new Error('An account with this email address already exists.');
    }

    // Encrypt Email with AES-256-GCM
    const encryptedEmail = encryptAES(normalizedEmail);

    // Hash Password with Bcrypt
    const passwordHash = await hashPassword(password);

    const newUser = {
        id: 'usr_' + crypto.randomBytes(8).toString('hex'),
        fullName: fullName ? fullName.trim() : 'Anonymous User',
        encryptedEmail: encryptedEmail,
        emailBlindIndex: blindIndex,
        passwordHash: passwordHash,
        createdAt: new Date().toISOString(),
        lastLogin: null
    };

    db.users.push(newUser);
    writeDb(db);

    return {
        id: newUser.id,
        fullName: newUser.fullName,
        email: normalizedEmail,
        createdAt: newUser.createdAt
    };
}

/**
 * Authenticate user credentials
 * - Uses blind index to retrieve user record
 * - Verifies password hash using Bcrypt
 * - Decrypts email for session profile
 */
async function authenticateUser({ email, password }) {
    const db = readDb();
    const normalizedEmail = email.trim().toLowerCase();
    const blindIndex = computeBlindIndex(normalizedEmail);

    const user = db.users.find(u => u.emailBlindIndex === blindIndex);
    if (!user) {
        throw new Error('Invalid email or password.');
    }

    // Constant-time password verification
    const isMatch = await verifyPassword(password, user.passwordHash);
    if (!isMatch) {
        throw new Error('Invalid email or password.');
    }

    // Decrypt email for profile
    const decryptedEmail = decryptAES(user.encryptedEmail);

    // Update lastLogin
    user.lastLogin = new Date().toISOString();
    writeDb(db);

    return {
        id: user.id,
        fullName: user.fullName,
        email: decryptedEmail,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
    };
}

/**
 * Find user by ID (for authenticated session)
 */
function findUserById(id) {
    const db = readDb();
    const user = db.users.find(u => u.id === id);
    if (!user) return null;

    return {
        id: user.id,
        fullName: user.fullName,
        email: decryptAES(user.encryptedEmail),
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        encryptedRecordPreview: {
            encryptedEmail: user.encryptedEmail,
            emailBlindIndex: user.emailBlindIndex,
            passwordHash: user.passwordHash
        }
    };
}

/**
 * Get sanitized dump of DB demonstrating encryption at rest
 */
function getStorageInspection() {
    const db = readDb();
    return db.users.map(u => ({
        id: u.id,
        fullName: u.fullName,
        encryptedEmail: u.encryptedEmail,
        emailBlindIndex: u.emailBlindIndex,
        passwordHash: u.passwordHash,
        createdAt: u.createdAt
    }));
}

module.exports = {
    initDb,
    registerUser,
    authenticateUser,
    findUserById,
    getStorageInspection
};
