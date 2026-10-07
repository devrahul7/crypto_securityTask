/**
 * Generates the Academic Security Report PDF matching the exact Softwarica / Coventry University template:
 * - Cover page with Softwarica / Coventry branding, ST6005CEM Security, student metadata
 * - Table of Contents with dot leaders
 * - Table of Figures with dot leaders
 * - Certificate evidence with Figure 1 & data table
 * - Frontend Implementation (Signup page, Figure 2 & Wireshark capture Figure 3)
 * - Login page (Figure 4 & Wireshark capture Figure 5)
 * - Functional Test Results Table (11 test cases)
 * - Exact double-line academic page borders & Times New Roman typography
 */

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const ACADEMIC_DIR = path.join(__dirname, '../screenshots/academic');
const OUTPUT_PDF = path.join(__dirname, '../Security_Implementation_Report.pdf');

function getBase64(filename) {
    const filePath = path.join(ACADEMIC_DIR, filename);
    if (!fs.existsSync(filePath)) {
        console.warn(`[WARN] Image not found: ${filePath}`);
        return '';
    }
    const ext = path.extname(filename).replace('.', '');
    const data = fs.readFileSync(filePath).toString('base64');
    return `data:image/${ext};base64,${data}`;
}

const imgCover = getBase64('cover_page.png');
const imgCert = getBase64('figure1_certificate.png');
const imgSignup = getBase64('figure2_signup.png');
const imgSignupWs = getBase64('figure3_signup_capture.png');
const imgLogin = getBase64('figure4_login.png');
const imgLoginWs = getBase64('figure5_login_capture.png');

const reportHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ST6005CEM Security Report</title>
<style>
  @page {
    size: A4;
    margin: 14mm 14mm 14mm 14mm;
  }
  @page :first {
    margin: 0;
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 0;
    font-family: 'Times New Roman', Times, serif;
    color: #000000;
    background: #ffffff;
    font-size: 12pt;
    line-height: 1.5;
  }

  .page-break {
    page-break-after: always;
    break-after: page;
  }

  /* Academic Double Border Page Container */
  .academic-page {
    height: 1045px;
    border: 3px double #000000;
    padding: 42px 48px;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    position: relative;
    background: #ffffff;
  }

  /* Cover Page Full Bleed */
  .cover-container {
    width: 100vw;
    height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    background: #000c1e;
    overflow: hidden;
  }
  .cover-img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  /* Titles */
  h1.toc-title {
    text-align: center;
    font-size: 16pt;
    font-weight: bold;
    margin-top: 15px;
    margin-bottom: 25px;
  }
  h1.section-title {
    font-size: 16pt;
    font-weight: bold;
    margin-top: 5px;
    margin-bottom: 12px;
  }
  h2.sub-title {
    font-size: 14pt;
    font-weight: bold;
    margin-top: 10px;
    margin-bottom: 8px;
  }

  p.desc {
    margin: 0 0 16px 0;
    text-align: justify;
    line-height: 1.45;
  }

  /* Table of Contents & Dot Leaders */
  .toc-list {
    margin-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .toc-item {
    display: flex;
    align-items: baseline;
    font-size: 12pt;
  }
  .toc-item.bold {
    font-weight: bold;
  }
  .toc-item.sub {
    padding-left: 28px;
  }
  .toc-text {
    flex-shrink: 0;
  }
  .toc-dots {
    flex-grow: 1;
    border-bottom: 1.5px dotted #000000;
    margin: 0 6px;
    height: 1em;
  }
  .toc-page {
    flex-shrink: 0;
  }

  /* Figure and Captions */
  .fig-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin-top: 15px;
    flex: 1;
  }
  .fig-img {
    max-width: 95%;
    max-height: 520px;
    object-fit: contain;
    border: 1px solid #d0d0d0;
  }
  .fig-img-ws {
    max-width: 98%;
    max-height: 680px;
    object-fit: contain;
    border: 1px solid #a0a0a0;
  }
  .fig-caption {
    text-align: center;
    font-weight: bold;
    font-style: italic;
    margin-top: 18px;
    font-size: 12pt;
  }

  /* Data Table */
  table.data-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 25px;
    font-size: 11pt;
  }
  table.data-table th, table.data-table td {
    border: 1px solid #cbd5e1;
    padding: 10px 14px;
    text-align: left;
    vertical-align: middle;
  }
  table.data-table th {
    background-color: #f8fafc;
    font-weight: bold;
  }
  table.data-table tr:nth-child(even) {
    background-color: #fcfcfc;
  }

  /* Test Results Table */
  table.test-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 14px;
    font-size: 9.5pt;
    line-height: 1.35;
  }
  table.test-table th, table.test-table td {
    border: 1px solid #cbd5e1;
    padding: 6px 8px;
    text-align: left;
    vertical-align: middle;
  }
  table.test-table th {
    background-color: #f8fafc;
    font-weight: bold;
    font-size: 10pt;
  }
  table.test-table td.col-num {
    width: 25px;
    text-align: center;
    font-weight: bold;
  }
  table.test-table td.col-test {
    width: 38%;
  }
  table.test-table td.col-exp {
    width: 26%;
  }
  table.test-table td.col-res {
    width: 36%;
  }
</style>
</head>
<body>

<!-- PAGE 1: COVER PAGE -->
<div class="cover-container page-break">
  <img src="${imgCover}" class="cover-img" alt="Cover Page">
</div>

<!-- PAGE 2: TABLE OF CONTENTS -->
<div class="academic-page page-break">
  <h1 class="toc-title">Table of Contents</h1>
  <div class="toc-list">
    <div class="toc-item bold">
      <span class="toc-text">Certificate evidence</span>
      <span class="toc-dots"></span>
      <span class="toc-page">4</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Frontend Implementation</span>
      <span class="toc-dots"></span>
      <span class="toc-page">6</span>
    </div>
    <div class="toc-item sub">
      <span class="toc-text">Signup page</span>
      <span class="toc-dots"></span>
      <span class="toc-page">6</span>
    </div>
    <div class="toc-item sub">
      <span class="toc-text">Login page</span>
      <span class="toc-dots"></span>
      <span class="toc-page">8</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Functional Test Results</span>
      <span class="toc-dots"></span>
      <span class="toc-page">10</span>
    </div>
  </div>
</div>

<!-- PAGE 3: TABLE OF FIGURES -->
<div class="academic-page page-break">
  <h1 class="toc-title">Table of Figures</h1>
  <div class="toc-list">
    <div class="toc-item bold">
      <span class="toc-text">Figure 1: Certificate</span>
      <span class="toc-dots"></span>
      <span class="toc-page">4</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Figure 2:signup page</span>
      <span class="toc-dots"></span>
      <span class="toc-page">6</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Figure 3: signup capture</span>
      <span class="toc-dots"></span>
      <span class="toc-page">7</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Figure 4:Login Page</span>
      <span class="toc-dots"></span>
      <span class="toc-page">8</span>
    </div>
    <div class="toc-item bold">
      <span class="toc-text">Figure 5: Login capture</span>
      <span class="toc-dots"></span>
      <span class="toc-page">9</span>
    </div>
  </div>
</div>

<!-- PAGE 4: CERTIFICATE EVIDENCE -->
<div class="academic-page page-break">
  <h1 class="section-title">Certificate evidence</h1>
  <p class="desc">Figure 1 shows the certificate presented by the server as seen in the browser Certificate Viewer.</p>
  <div class="fig-center">
    <img src="${imgCert}" class="fig-img" alt="Certificate Viewer Screenshot">
    <div class="fig-caption">Figure 1: Certificate</div>
  </div>
</div>

<!-- PAGE 5: CERTIFICATE DATA TABLE -->
<div class="academic-page page-break">
  <table class="data-table">
    <thead>
      <tr>
        <th style="width: 32%;">Field</th>
        <th>Value</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Common Name (CN)</strong></td>
        <td>localhost</td>
      </tr>
      <tr>
        <td><strong>Issued by</strong></td>
        <td>localhost (self-signed)</td>
      </tr>
      <tr>
        <td><strong>Valid from</strong></td>
        <td>Wednesday, 7 October 2026, 8:41:20 AM</td>
      </tr>
      <tr>
        <td><strong>Valid until</strong></td>
        <td>Tuesday, 9 January 2029, 8:41:20 AM</td>
      </tr>
      <tr>
        <td><strong>SHA-256 fingerprint (certificate)</strong></td>
        <td style="font-family: Consolas, monospace; font-size: 10.5pt; word-break: break-all;">636137f0c96454f35e532ad477c5eb97ae53c1fc408a8fd12e09725f1ca96fc6</td>
      </tr>
      <tr>
        <td><strong>SHA-256 fingerprint (public key)</strong></td>
        <td style="font-family: Consolas, monospace; font-size: 10.5pt; word-break: break-all;">cae2e8fc1d0582da70ee1b6b1fcc1e3f24c5465b8161171eee5d5e892613f76f</td>
      </tr>
    </tbody>
  </table>
</div>

<!-- PAGE 6: FRONTEND IMPLEMENTATION - SIGNUP PAGE -->
<div class="academic-page page-break">
  <h1 class="section-title">Frontend Implementation</h1>
  <p class="desc">
    The frontend consists of a signup page and a login page. Both are loaded from https://localhost:3443 and submit to relative HTTPS endpoints, so the browser cannot downgrade to HTTP.
  </p>
  <h2 class="sub-title">Signup page</h2>
  <p class="desc">
    The page collects username, email and password. The password field is masked and states the 12-character minimum. Invalid emails are rejected by the server.
  </p>
  <div class="fig-center">
    <img src="${imgSignup}" class="fig-img" style="max-height: 440px;" alt="Signup page">
    <div class="fig-caption">Figure 2:signup page</div>
  </div>
</div>

<!-- PAGE 7: SIGNUP CAPTURE -->
<div class="academic-page page-break">
  <div class="fig-center">
    <img src="${imgSignupWs}" class="fig-img-ws" alt="Signup capture">
    <div class="fig-caption">Figure 3: signup capture</div>
  </div>
</div>

<!-- PAGE 8: FRONTEND IMPLEMENTATION - LOGIN PAGE -->
<div class="academic-page page-break">
  <h2 class="sub-title" style="margin-top: 5px;">Login page</h2>
  <p class="desc">
    The login page accepts a username or the registered email together with the password and submits them to /api/login.
  </p>
  <div class="fig-center">
    <img src="${imgLogin}" class="fig-img" style="max-height: 520px;" alt="Login page">
    <div class="fig-caption">Figure 4:Login Page</div>
  </div>
</div>

<!-- PAGE 9: LOGIN CAPTURE -->
<div class="academic-page page-break">
  <div class="fig-center">
    <img src="${imgLoginWs}" class="fig-img-ws" alt="Login capture">
    <div class="fig-caption">Figure 5: Login capture</div>
  </div>
</div>

<!-- PAGE 10: FUNCTIONAL TEST RESULTS -->
<div class="academic-page">
  <h1 class="section-title">Functional Test Results</h1>
  <p class="desc">
    The authentication flow was exercised with HTTPS requests to https://localhost:3443. Every case produced the expected result.
  </p>
  <table class="test-table">
    <thead>
      <tr>
        <th class="col-num">#</th>
        <th class="col-test">Test</th>
        <th class="col-exp">Expected</th>
        <th class="col-res">Result</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="col-num">1</td>
        <td>Signup with invalid email "not-an-email"</td>
        <td>Rejected</td>
        <td>400: A valid email address is required</td>
      </tr>
      <tr>
        <td class="col-num">2</td>
        <td>Signup with 5-character password</td>
        <td>Rejected</td>
        <td>400: Password must be at least 12 characters</td>
      </tr>
      <tr>
        <td class="col-num">3</td>
        <td>Signup with valid data</td>
        <td>Account created</td>
        <td>201: Account created</td>
      </tr>
      <tr>
        <td class="col-num">4</td>
        <td>Signup again with same username and email</td>
        <td>Rejected</td>
        <td>409: Username or email already registered</td>
      </tr>
      <tr>
        <td class="col-num">5</td>
        <td>Login with wrong password</td>
        <td>Rejected</td>
        <td>401: Invalid credentials</td>
      </tr>
      <tr>
        <td class="col-num">6</td>
        <td>Login with username and correct password</td>
        <td>Success, cookie set</td>
        <td>200: Login successful; cookie HttpOnly, Secure, SameSite=Strict</td>
      </tr>
      <tr>
        <td class="col-num">7</td>
        <td>Login with email (different letter case)</td>
        <td>Success</td>
        <td>200: Login successful (blind index match)</td>
      </tr>
      <tr>
        <td class="col-num">8</td>
        <td>Read profile with session cookie</td>
        <td>Email decrypted for owner</td>
        <td>200: student01, student@example.com</td>
      </tr>
      <tr>
        <td class="col-num">9</td>
        <td>Read profile without cookie</td>
        <td>Denied</td>
        <td>401: Not authenticated</td>
      </tr>
      <tr>
        <td class="col-num">10</td>
        <td>Plain HTTP request to port 3443</td>
        <td>No response</td>
        <td>Connection fails (HTTP code 000)</td>
      </tr>
      <tr>
        <td class="col-num">11</td>
        <td>TLS negotiation</td>
        <td>TLS 1.3</td>
        <td>TLSv1.3, TLS_AES_256_GCM_SHA384, X25519, certificate verified</td>
      </tr>
    </tbody>
  </table>
</div>

</body>
</html>
`;

(async () => {
    console.log('[ACADEMIC PDF] Compiling publication-grade academic PDF report...');
    const browser = await puppeteer.launch({
        executablePath: EDGE_PATH,
        headless: 'new',
        args: ['--no-sandbox', '--disable-gpu']
    });

    const page = await browser.newPage();
    await page.setContent(reportHtml, { waitUntil: 'domcontentloaded' });
    await new Promise(r => setTimeout(r, 600));

    console.log('[ACADEMIC PDF] Printing to PDF...');
    await page.pdf({
        path: OUTPUT_PDF,
        format: 'A4',
        printBackground: true,
        margin: {
            top: '0mm',
            bottom: '0mm',
            left: '0mm',
            right: '0mm'
        }
    });

    await browser.close();
    console.log(`[ACADEMIC PDF] Success! PDF compiled at: ${OUTPUT_PDF}`);
})();
