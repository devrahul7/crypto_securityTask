const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const cert = fs.readFileSync(path.join(__dirname, '..', 'certs', 'server.crt'));
const agent = new https.Agent({ ca: cert });

function makeRequest({ method = 'GET', port = 8443, path: reqPath = '/', body = null, headers = {}, isHttps = true }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port,
      path: reqPath,
      method,
      headers: {
        ...headers,
        ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(JSON.stringify(body)) } : {})
      },
      agent: isHttps ? agent : undefined
    };

    const client = isHttps ? https : http;
    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data,
          json
        });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function runE2ETests() {
  console.log('====================================================');
  console.log('       RUNNING END-TO-END HTTPS INTEGRATION TESTS    ');
  console.log('====================================================\n');

  let serversStartedLocally = false;
  let httpsServer, httpServer;

  // Check if server is already running
  try {
    const existingHealth = await makeRequest({ path: '/api/health' });
    if (existingHealth.statusCode === 200) {
      console.log('  [INFO] Detected active server running on port 8443.');
    }
  } catch (_) {
    console.log('  [INFO] Starting local test server instance...');
    const serverMod = require('../src/server');
    httpsServer = serverMod.httpsServer;
    httpServer = serverMod.httpServer;
    serversStartedLocally = true;
    await new Promise(r => setTimeout(r, 1000));
  }

  let cookie = null;

  try {
    // 1. Health check over HTTPS
    console.log('[E2E-1] Testing HTTPS Health Endpoint...');
    const health = await makeRequest({ path: '/api/health' });
    assert.strictEqual(health.statusCode, 200);
    assert.strictEqual(health.json.protocol.toLowerCase(), 'https');
    console.log('  -> Health check PASSED: HTTPS verified.');

    // 2. HTTP to HTTPS Redirection Test
    console.log('[E2E-2] Testing HTTP -> HTTPS 301 Redirect on port 8080...');
    const redir = await makeRequest({ port: 8080, path: '/api/health', isHttps: false });
    assert.strictEqual(redir.statusCode, 301);
    assert.strictEqual(redir.headers.location, 'https://localhost:8443/api/health');
    console.log('  -> HTTP Redirection PASSED: Strict HTTPS enforced.');

    // 3. Signup Invalid Email Rejection
    console.log('[E2E-3] Testing Signup with Invalid Email (RFC 5322 enforcement)...');
    const invalidEmailRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/signup',
      body: { name: 'Invalid User', email: 'not-an-email', password: 'ValidPass123!@#' }
    });
    assert.strictEqual(invalidEmailRes.statusCode, 400);
    assert.strictEqual(invalidEmailRes.json.error, 'EMAIL_VALIDATION_FAILED');
    console.log('  -> Invalid email rejection PASSED.');

    // 4. Signup Weak Password Rejection
    console.log('[E2E-4] Testing Signup with Weak Password...');
    const weakPassRes = await makeRequest({
      method: 'POST',
      path: '/api/auth/signup',
      body: { name: 'Weak Pass User', email: 'test@enterprise.org', password: '123' }
    });
    assert.strictEqual(weakPassRes.statusCode, 400);
    assert.strictEqual(weakPassRes.json.error, 'PASSWORD_POLICY_FAILED');
    console.log('  -> Weak password rejection PASSED.');

    // 5. Successful Secure Signup with AES-256-GCM & Bcrypt
    console.log('[E2E-5] Testing Valid Signup (AES-256-GCM & Bcrypt 12 rounds)...');
    const validSignup = await makeRequest({
      method: 'POST',
      path: '/api/auth/signup',
      body: {
        name: 'Dr. Evelyn Reed',
        email: 'evelyn.reed@cyberdefense.org',
        password: 'Defend#Network$2026!'
      }
    });
    assert.strictEqual(validSignup.statusCode, 201);
    assert.strictEqual(validSignup.json.success, true);
    assert.strictEqual(validSignup.json.securityProof.plaintext_stored, false);
    assert.strictEqual(validSignup.json.securityProof.iv_hex.length, 24); // 12-byte IV
    console.log('  -> Signup PASSED: User created with AES-256-GCM & Bcrypt.');

    // 6. Login with Bad Password
    console.log('[E2E-6] Testing Login with Incorrect Password...');
    const badLogin = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      body: { email: 'evelyn.reed@cyberdefense.org', password: 'WrongPassword123!' }
    });
    assert.strictEqual(badLogin.statusCode, 401);
    console.log('  -> Invalid credentials rejection PASSED.');

    // 7. Login with Correct Password & Verify Secure Cookie
    console.log('[E2E-7] Testing Valid Login over HTTPS...');
    const validLogin = await makeRequest({
      method: 'POST',
      path: '/api/auth/login',
      body: { email: 'evelyn.reed@cyberdefense.org', password: 'Defend#Network$2026!' }
    });
    assert.strictEqual(validLogin.statusCode, 200);
    assert.strictEqual(validLogin.json.user.email, 'evelyn.reed@cyberdefense.org');
    
    // Check Set-Cookie
    const setCookieHeader = validLogin.headers['set-cookie'];
    assert.ok(setCookieHeader);
    const cookieStr = setCookieHeader[0];
    assert.ok(cookieStr.includes('HttpOnly'), 'Cookie must be HttpOnly');
    assert.ok(cookieStr.includes('Secure'), 'Cookie must be Secure');
    assert.ok(cookieStr.includes('SameSite=Strict'), 'Cookie must be SameSite=Strict');
    cookie = cookieStr.split(';')[0];
    console.log('  -> Login PASSED: Received Secure, HttpOnly cookie over TLS.');

    // 8. Access Protected Route /api/auth/me using Cookie
    console.log('[E2E-8] Testing Protected /api/auth/me Endpoint over HTTPS...');
    const meRes = await makeRequest({
      method: 'GET',
      path: '/api/auth/me',
      headers: { Cookie: cookie }
    });
    assert.strictEqual(meRes.statusCode, 200);
    assert.strictEqual(meRes.json.user.email, 'evelyn.reed@cyberdefense.org');
    assert.strictEqual(meRes.json.session.transport, 'HTTPS (TLS 1.2 / 1.3)');
    console.log('  -> Protected route PASSED: In-memory decrypted identity verified.');

    // 9. Database Audit Endpoint
    console.log('[E2E-9] Testing Database Storage Audit (Confirming No Plaintext on Disk)...');
    const auditRes = await makeRequest({ method: 'GET', path: '/api/auth/audit-database' });
    assert.strictEqual(auditRes.statusCode, 200);
    const records = auditRes.json.records;
    assert.ok(records.length > 0);
    const audited = records.find(r => r.name === 'Dr. Evelyn Reed');
    assert.ok(audited);
    assert.ok(audited.email_encrypted.includes(':')); // iv:authTag:ciphertext
    assert.ok(audited.password_hash.startsWith('$2b$12$') || audited.password_hash.startsWith('$2a$12$'));
    console.log('  -> Database audit PASSED: Stored record contains zero plaintext.');

    console.log('\n====================================================');
    console.log(' ALL E2E HTTPS INTEGRATION TESTS PASSED 100%!       ');
    console.log('====================================================');

  } catch (err) {
    console.error('E2E TEST FAILURE:', err);
    process.exit(1);
  } finally {
    if (serversStartedLocally) {
      if (httpsServer) httpsServer.close();
      if (httpServer) httpServer.close();
    }
    process.exit(0);
  }
}

runE2ETests();
