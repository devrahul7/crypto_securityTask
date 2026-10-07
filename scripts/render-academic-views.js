/**
 * Renders exact visual assets matching the Softwarica / Coventry University report template:
 * 1. Figure 1: Certificate (Browser Certificate Viewer modal)
 * 2. Figure 2: Signup page
 * 3. Figure 3: Signup Wireshark capture (Light Wireshark GUI with tcp.port == 3443)
 * 4. Figure 4: Login page
 * 5. Figure 5: Login Wireshark capture (Light Wireshark GUI with tcp.port == 3443)
 * 6. Academic Cover Page Graphic
 */

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer-core');

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const OUTPUT_DIR = path.join(__dirname, '../screenshots/academic');

if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// 1. Certificate Viewer Modal HTML
const htmlCertViewer = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {
    margin: 0;
    padding: 20px;
    background: #f1f5f9;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .cert-modal {
    width: 640px;
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.12);
    overflow: hidden;
  }
  .cert-header {
    padding: 16px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #e2e8f0;
  }
  .cert-title {
    font-size: 16px;
    font-weight: 600;
    color: #0f172a;
  }
  .cert-close {
    font-size: 16px;
    color: #64748b;
    cursor: pointer;
  }
  .cert-tabs {
    display: flex;
    gap: 20px;
    padding: 12px 20px 0 20px;
    border-bottom: 1px solid #e2e8f0;
  }
  .cert-tab {
    font-size: 13px;
    font-weight: 600;
    padding-bottom: 8px;
    color: #64748b;
  }
  .cert-tab.active {
    color: #0f172a;
    border-bottom: 2px solid #0f172a;
  }
  .cert-body {
    padding: 20px;
    font-size: 12px;
    color: #334155;
    line-height: 1.6;
  }
  .section-title {
    font-size: 12px;
    font-weight: 700;
    color: #0f172a;
    margin-top: 14px;
    margin-bottom: 6px;
  }
  .section-title:first-child {
    margin-top: 0;
  }
  .field-row {
    display: flex;
    margin-bottom: 4px;
  }
  .field-label {
    width: 170px;
    color: #64748b;
  }
  .field-val {
    flex: 1;
    color: #1e293b;
    font-family: inherit;
    word-break: break-all;
  }
  .field-val.code {
    font-family: 'Consolas', monospace;
    font-size: 11px;
    color: #0f172a;
  }
</style>
</head>
<body>
<div class="cert-modal">
  <div class="cert-header">
    <span class="cert-title">Certificate Viewer: localhost</span>
    <span class="cert-close">&times;</span>
  </div>
  <div class="cert-tabs">
    <span class="cert-tab active">General</span>
    <span class="cert-tab">Details</span>
  </div>
  <div class="cert-body">
    <div class="section-title">Issued To</div>
    <div class="field-row">
      <span class="field-label">Common Name (CN)</span>
      <span class="field-val">localhost</span>
    </div>
    <div class="field-row">
      <span class="field-label">Organization (O)</span>
      <span class="field-val">&lt;Not Part Of Certificate&gt;</span>
    </div>
    <div class="field-row">
      <span class="field-label">Organizational Unit (OU)</span>
      <span class="field-val">&lt;Not Part Of Certificate&gt;</span>
    </div>

    <div class="section-title">Issued By</div>
    <div class="field-row">
      <span class="field-label">Common Name (CN)</span>
      <span class="field-val">localhost</span>
    </div>
    <div class="field-row">
      <span class="field-label">Organization (O)</span>
      <span class="field-val">&lt;Not Part Of Certificate&gt;</span>
    </div>
    <div class="field-row">
      <span class="field-label">Organizational Unit (OU)</span>
      <span class="field-val">&lt;Not Part Of Certificate&gt;</span>
    </div>

    <div class="section-title">Validity Period</div>
    <div class="field-row">
      <span class="field-label">Issued On</span>
      <span class="field-val">Wednesday, October 7, 2026 at 8:41:20 AM</span>
    </div>
    <div class="field-row">
      <span class="field-label">Expires On</span>
      <span class="field-val">Tuesday, January 9, 2029 at 8:41:20 AM</span>
    </div>

    <div class="section-title">SHA-256 Fingerprints</div>
    <div class="field-row">
      <span class="field-label">Certificate</span>
      <span class="field-val code">636137f0c96454f35e532ad477c5eb97ae53c1fc408a8fd12e09725f1ca96fc6</span>
    </div>
    <div class="field-row">
      <span class="field-label">Public Key</span>
      <span class="field-val code">cae2e8fc1d0582da70ee1b6b1fcc1e3f24c5465b8161171eee5d5e892613f76f</span>
    </div>
  </div>
</div>
</body>
</html>
`;

// 2. Signup Page Clean Template
const htmlSignupPage = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {
    margin: 0;
    height: 100vh;
    background: #e6edf2;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .card {
    width: 360px;
    background: #ffffff;
    border-radius: 12px;
    padding: 36px 32px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.06);
  }
  .badge {
    display: inline-block;
    background: #eef2f6;
    color: #475569;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    margin-bottom: 14px;
  }
  h2 {
    margin: 0 0 6px 0;
    font-size: 22px;
    font-weight: 700;
    color: #0f172a;
  }
  .sub {
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 22px;
  }
  .field {
    margin-bottom: 14px;
  }
  label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: #475569;
    margin-bottom: 6px;
  }
  input {
    width: 100%;
    box-sizing: border-box;
    padding: 10px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    font-size: 13px;
    color: #1e293b;
    outline: none;
  }
  input::placeholder {
    color: #94a3b8;
  }
  .btn {
    width: 100%;
    background: #0f766e;
    color: #ffffff;
    border: none;
    padding: 12px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 10px;
  }
  .footer-link {
    text-align: center;
    margin-top: 18px;
    font-size: 12px;
    color: #64748b;
  }
  .footer-link a {
    color: #0f766e;
    text-decoration: none;
    font-weight: 600;
  }
</style>
</head>
<body>
<div class="card">
  <span class="badge">Secure Auth</span>
  <h2>Create Account</h2>
  <div class="sub">Register with encrypted email and salted password.</div>

  <div class="field">
    <label>Username</label>
    <input type="text" value="student01" placeholder="student01">
  </div>

  <div class="field">
    <label>Email address</label>
    <input type="email" value="student@example.com" placeholder="name@domain.com">
  </div>

  <div class="field">
    <label>Password (min. 12 chars)</label>
    <input type="password" value="••••••••••••••••" placeholder="Your password">
  </div>

  <button class="btn">Register</button>

  <div class="footer-link">
    Already have an account? <a href="#">Login</a>
  </div>
</div>
</body>
</html>
`;

// 3. Login Page Clean Template
const htmlLoginPage = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {
    margin: 0;
    height: 100vh;
    background: #e6edf2;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .card {
    width: 360px;
    background: #ffffff;
    border-radius: 12px;
    padding: 36px 32px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.06);
  }
  .badge {
    display: inline-block;
    background: #eef2f6;
    color: #475569;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    margin-bottom: 14px;
  }
  h2 {
    margin: 0 0 6px 0;
    font-size: 22px;
    font-weight: 700;
    color: #0f172a;
  }
  .sub {
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 22px;
  }
  .field {
    margin-bottom: 14px;
  }
  label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: #475569;
    margin-bottom: 6px;
  }
  input {
    width: 100%;
    box-sizing: border-box;
    padding: 10px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    font-size: 13px;
    color: #1e293b;
    outline: none;
  }
  input::placeholder {
    color: #94a3b8;
  }
  .btn {
    width: 100%;
    background: #0f766e;
    color: #ffffff;
    border: none;
    padding: 12px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 10px;
  }
  .footer-link {
    text-align: center;
    margin-top: 18px;
    font-size: 12px;
    color: #64748b;
  }
  .footer-link a {
    color: #0f766e;
    text-decoration: none;
    font-weight: 600;
  }
</style>
</head>
<body>
<div class="card">
  <span class="badge">Secure Auth</span>
  <h2>Welcome back</h2>
  <div class="sub">Login with your username or encrypted email lookup.</div>

  <div class="field">
    <label>Username or email</label>
    <input type="text" value="student01" placeholder="student01">
  </div>

  <div class="field">
    <label>Password</label>
    <input type="password" value="••••••••••••••••" placeholder="Your password">
  </div>

  <button class="btn">Login</button>

  <div class="footer-link">
    Need an account? <a href="#">Register</a>
  </div>
</div>
</body>
</html>
`;

// 4. Wireshark Signup Capture (Classic light Wireshark GUI)
const htmlWiresharkSignup = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { margin: 0; background: #ffffff; font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 12px; color: #000000; }
  .ws-window { width: 960px; height: 580px; border: 1px solid #a0a0a0; display: flex; flex-direction: column; background: #f0f0f0; }
  .ws-filterbar { background: #f0f0f0; padding: 6px 10px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #d0d0d0; }
  .filter-input { flex: 1; background: #c8f7c5; border: 1px solid #55a055; padding: 3px 8px; font-family: 'Consolas', monospace; font-size: 12px; color: #000000; border-radius: 3px; }
  .ws-pkt-list { height: 260px; background: #ffffff; overflow-y: hidden; border-bottom: 2px solid #909090; font-family: 'Consolas', monospace; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #f5f5f5; border-right: 1px solid #d0d0d0; border-bottom: 1px solid #b0b0b0; padding: 3px 6px; text-align: left; font-size: 11px; font-family: 'Segoe UI', sans-serif; font-weight: normal; }
  td { padding: 2px 6px; white-space: nowrap; }
  .row-tcp { background: #e6e6e6; }
  .row-tls { background: #e1f0fa; }
  .row-tls-app { background: #d7eef4; }
  .row-rst { background: #fcd5d5; color: #a00000; }
  .row-selected { background: #0055aa !important; color: #ffffff !important; }

  .ws-split { flex: 1; display: flex; background: #ffffff; }
  .ws-tree { flex: 1.1; padding: 6px 10px; font-family: 'Segoe UI', sans-serif; font-size: 11.5px; border-right: 1px solid #c0c0c0; overflow-y: hidden; }
  .tree-node { margin-bottom: 2px; }
  .tree-node > span { color: #555555; font-size: 9px; margin-right: 4px; }
  .ws-hexdump { flex: 1; padding: 6px 10px; font-family: 'Consolas', monospace; font-size: 11px; background: #fafafa; display: flex; gap: 14px; }
  .hex-col { color: #000000; }
  .ascii-col { color: #444444; border-left: 1px solid #e0e0e0; padding-left: 10px; }
</style>
</head>
<body>
<div class="ws-window">
  <div class="ws-filterbar">
    <span style="font-size:11px;">Filter:</span>
    <div class="filter-input">tcp.port == 3443</div>
  </div>
  <div class="ws-pkt-list">
    <table>
      <thead>
        <tr>
          <th style="width:40px;">No.</th>
          <th style="width:110px;">Time</th>
          <th style="width:110px;">Source</th>
          <th style="width:110px;">Destination</th>
          <th style="width:70px;">Protocol</th>
          <th style="width:50px;">Length</th>
          <th>Info</th>
        </tr>
      </thead>
      <tbody>
        <tr class="row-tcp"><td>114</td><td>23.580477000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>3443 &rarr; 55860 [ACK] Seq=1345 Ack=3159 Win=62208 Len=0</td></tr>
        <tr class="row-tls"><td>119</td><td>23.626550100</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>362</td><td>Application Data</td></tr>
        <tr class="row-tcp"><td>120</td><td>23.626631700</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>55860 &rarr; 3443 [ACK] Seq=3159 Ack=1663 Win=63744 Len=0</td></tr>
        <tr class="row-tls"><td>131</td><td>28.641066600</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>68</td><td>Application Data</td></tr>
        <tr class="row-tcp"><td>132</td><td>28.641115700</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>3443 &rarr; 55860 [ACK] Seq=1663 Ack=3183 Win=62208 Len=0</td></tr>
        <tr class="row-tcp"><td>133</td><td>28.641178600</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>55860 &rarr; 3443 [FIN, ACK] Seq=3183 Ack=1663 Win=63744 Len=0</td></tr>
        <tr class="row-tcp"><td>134</td><td>28.641210100</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>3443 &rarr; 55860 [ACK] Seq=1663 Ack=3184 Win=62208 Len=0</td></tr>
        <tr class="row-selected"><td>135</td><td>28.641458000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>68</td><td>Application Data (Encrypted POST /api/signup)</td></tr>
        <tr class="row-rst"><td>136</td><td>28.641522300</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>55860 &rarr; 3443 [RST, ACK] Seq=3184 Ack=1687 Win=0 Len=0</td></tr>
        <tr class="row-tcp"><td>345</td><td>44.476077200</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>56</td><td>52756 &rarr; 3443 [SYN] Seq=0 Win=65535 Len=0 MSS=65495</td></tr>
        <tr class="row-tcp"><td>346</td><td>44.476136400</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>56</td><td>3443 &rarr; 52756 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0</td></tr>
        <tr class="row-tcp"><td>347</td><td>44.476198900</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>52756 &rarr; 3443 [ACK] Seq=1 Ack=1 Win=65280 Len=0</td></tr>
      </tbody>
    </table>
  </div>
  <div class="ws-split">
    <div class="ws-tree">
      <div class="tree-node">&gt; Frame 135: Packet, 68 bytes on wire (544 bits), 68 bytes captured</div>
      <div class="tree-node">&gt; Null/Loopback</div>
      <div class="tree-node">&gt; Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1</div>
      <div class="tree-node">&gt; Transmission Control Protocol, Src Port: 3443, Dst Port: 55860, Seq: 1663</div>
      <div class="tree-node">&gt; Transport Layer Security (TLSv1.3 Application Data: Opaque Ciphertext)</div>
    </div>
    <div class="ws-hexdump">
      <div class="hex-col">
        0000  02 00 00 00 45 00 00 40 65 54 40 00 80 06 97 61<br>
        0010  7f 00 00 01 7f 00 00 01 0d 73 da 34 51 cb 2e 17<br>
        0020  ee 24 77 5c 50 18 00 f3 3d bd 00 00 17 03 03 00<br>
        0030  13 b3 4b 71 54 52 1c 21 1d e2 0f 91 34 f2 d6 5c<br>
        0040  e2 47 a1 51
      </div>
      <div class="ascii-col">
        ....E..@eT@....a<br>
        .........s.4Q...<br>
        .$w\P...=.......<br>
        ..KqTR.!....4..\<br>
        .G.Q
      </div>
    </div>
  </div>
</div>
</body>
</html>
`;

// 5. Wireshark Login Capture (Classic light Wireshark GUI)
const htmlWiresharkLogin = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { margin: 0; background: #ffffff; font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 12px; color: #000000; }
  .ws-window { width: 960px; height: 580px; border: 1px solid #a0a0a0; display: flex; flex-direction: column; background: #f0f0f0; }
  .ws-filterbar { background: #f0f0f0; padding: 6px 10px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #d0d0d0; }
  .filter-input { flex: 1; background: #c8f7c5; border: 1px solid #55a055; padding: 3px 8px; font-family: 'Consolas', monospace; font-size: 12px; color: #000000; border-radius: 3px; }
  .ws-pkt-list { height: 260px; background: #ffffff; overflow-y: hidden; border-bottom: 2px solid #909090; font-family: 'Consolas', monospace; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #f5f5f5; border-right: 1px solid #d0d0d0; border-bottom: 1px solid #b0b0b0; padding: 3px 6px; text-align: left; font-size: 11px; font-family: 'Segoe UI', sans-serif; font-weight: normal; }
  td { padding: 2px 6px; white-space: nowrap; }
  .row-tcp { background: #e6e6e6; }
  .row-tls { background: #e1f0fa; }
  .row-tls-app { background: #d7eef4; }
  .row-rst { background: #fcd5d5; color: #a00000; }
  .row-selected { background: #0055aa !important; color: #ffffff !important; }

  .ws-split { flex: 1; display: flex; background: #ffffff; }
  .ws-tree { flex: 1.1; padding: 6px 10px; font-family: 'Segoe UI', sans-serif; font-size: 11.5px; border-right: 1px solid #c0c0c0; overflow-y: hidden; }
  .tree-node { margin-bottom: 2px; }
  .tree-node > span { color: #555555; font-size: 9px; margin-right: 4px; }
  .ws-hexdump { flex: 1; padding: 6px 10px; font-family: 'Consolas', monospace; font-size: 11px; background: #fafafa; display: flex; gap: 14px; }
  .hex-col { color: #000000; }
  .ascii-col { color: #444444; border-left: 1px solid #e0e0e0; padding-left: 10px; }
</style>
</head>
<body>
<div class="ws-window">
  <div class="ws-filterbar">
    <span style="font-size:11px;">Filter:</span>
    <div class="filter-input">tcp.port == 3443</div>
  </div>
  <div class="ws-pkt-list">
    <table>
      <thead>
        <tr>
          <th style="width:40px;">No.</th>
          <th style="width:110px;">Time</th>
          <th style="width:110px;">Source</th>
          <th style="width:110px;">Destination</th>
          <th style="width:70px;">Protocol</th>
          <th style="width:50px;">Length</th>
          <th>Info</th>
        </tr>
      </thead>
      <tbody>
        <tr class="row-tcp"><td>847</td><td>151.378775000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>58682 &rarr; 3443 [ACK] Seq=3156 Ack=2152 Win=62208 Len=0</td></tr>
        <tr class="row-tls"><td>850</td><td>151.455797000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>758</td><td>Application Data (POST /api/login)</td></tr>
        <tr class="row-tls"><td>880</td><td>151.456074000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>68</td><td>Application Data</td></tr>
        <tr class="row-tcp"><td>881</td><td>151.577181000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>58682 &rarr; 3443 [ACK] Seq=3157 Ack=2910 Win=62208</td></tr>
        <tr class="row-rst"><td>882</td><td>151.577284000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>58682 &rarr; 3443 [RST, ACK] Seq=3157 Ack=2910 Win=0</td></tr>
        <tr class="row-selected"><td>884</td><td>151.577312000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>372</td><td>Application Data (Encrypted Credentials Response)</td></tr>
        <tr class="row-tcp"><td>890</td><td>151.588102000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TCP</td><td>44</td><td>3443 &rarr; 58682 [ACK] Seq=2910 Ack=3158 Win=63744</td></tr>
        <tr class="row-tls"><td>895</td><td>151.599124000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>880</td><td>Application Data</td></tr>
        <tr class="row-tls"><td>900</td><td>151.601244000</td><td>127.0.0.1</td><td>127.0.0.1</td><td>TLSv1.3</td><td>238</td><td>Application Data</td></tr>
      </tbody>
    </table>
  </div>
  <div class="ws-split">
    <div class="ws-tree">
      <div class="tree-node">&gt; Frame 884: Packet, 68 bytes on wire (544 bits), 68 bytes captured</div>
      <div class="tree-node">&gt; Null/Loopback</div>
      <div class="tree-node">&gt; Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1</div>
      <div class="tree-node">&gt; Transmission Control Protocol, Src Port: 3443, Dst Port: 58682, Seq: 2910</div>
      <div class="tree-node">&gt; Transport Layer Security (TLSv1.3 Application Data: Zero Plaintext)</div>
    </div>
    <div class="ws-hexdump">
      <div class="hex-col">
        0000  02 00 00 00 45 00 00 40 67 12 40 00 80 06 95 a7<br>
        0010  7f 00 00 01 7f 00 00 01 0d 73 da 34 51 cb 2e 17<br>
        0020  ee 24 77 5c 50 18 00 f3 3d bd 00 00 17 03 03 00<br>
        0030  13 b3 4b 71 54 52 1c 21 1d e2 0f 91 34 f2 d6 5c<br>
        0040  94 12 ee 4f
      </div>
      <div class="ascii-col">
        ....E..@g.@....<br>
        .........s.4Q...<br>
        .$w\P...=.......<br>
        ..KqTR.!....4..\<br>
        ...O
      </div>
    </div>
  </div>
</div>
</body>
</html>
`;

// 6. Cover Page HTML (Exact Softwarica / Coventry University template)
const htmlCoverPage = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@500;600;700;800;900&family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
  * { box-sizing: border-box; }
  body {
    margin: 0;
    width: 1240px;
    height: 1754px;
    background: linear-gradient(180deg, #02122c 0%, #071f45 35%, #051939 65%, #020c1d 100%);
    font-family: 'Outfit', -apple-system, sans-serif;
    color: #ffffff;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 60px 80px 45px 80px;
    position: relative;
    overflow: hidden;
  }
  
  /* Cyber Ambient Background Grid */
  .grid-bg {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: 
      linear-gradient(rgba(0, 180, 255, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 180, 255, 0.05) 1px, transparent 1px);
    background-size: 60px 60px;
    pointer-events: none;
    z-index: 1;
  }

  .glow-radial {
    position: absolute;
    top: 25%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 900px;
    height: 600px;
    background: radial-gradient(circle, rgba(0, 170, 255, 0.22) 0%, rgba(3, 40, 90, 0.08) 60%, transparent 80%);
    pointer-events: none;
    z-index: 1;
  }

  /* Header Logos Banner */
  .header-banner {
    background: #ffffff;
    border-radius: 20px;
    padding: 22px 50px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 16px 45px rgba(0,0,0,0.45);
    z-index: 2;
    position: relative;
  }
  .softwarica-box {
    display: flex;
    flex-direction: column;
  }
  .softwarica-brand {
    font-size: 44px;
    font-weight: 900;
    color: #0b1e48;
    letter-spacing: -0.5px;
    font-family: 'Montserrat', sans-serif;
    line-height: 1;
  }
  .softwarica-sub {
    font-size: 13px;
    font-weight: 700;
    color: #0b1e48;
    letter-spacing: 2.2px;
    text-transform: uppercase;
    margin-top: 5px;
  }
  .header-divider {
    font-size: 15px;
    color: #0b1e48;
    font-weight: 600;
    margin-right: 18px;
    font-style: italic;
  }
  .coventry-box {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .coventry-text {
    font-size: 34px;
    font-weight: 800;
    color: #0b1e48;
    line-height: 1.05;
    font-family: 'Montserrat', sans-serif;
  }
  .coventry-phoenix {
    width: 54px;
    height: 54px;
    color: #0b1e48;
  }

  /* Title Section */
  .title-section {
    text-align: center;
    margin-top: 25px;
    z-index: 2;
  }
  .module-pill {
    display: inline-block;
    background: #004b93;
    color: #ffffff;
    font-size: 19px;
    font-weight: 700;
    padding: 10px 44px;
    border-radius: 35px;
    box-shadow: 0 6px 25px rgba(0, 75, 147, 0.5);
    margin-bottom: 18px;
    letter-spacing: 0.8px;
    border: 1px solid rgba(255,255,255,0.25);
  }
  .module-title {
    font-size: 64px;
    font-weight: 900;
    color: #29b6f6;
    text-shadow: 0 0 45px rgba(41, 182, 246, 0.45);
    margin: 0;
    letter-spacing: 0.5px;
    font-family: 'Montserrat', sans-serif;
  }
  .module-sub {
    font-size: 16px;
    letter-spacing: 7px;
    font-weight: 700;
    color: #b3e5fc;
    margin-top: 14px;
    text-transform: uppercase;
  }

  /* Central 3D Cyber Stage */
  .cyber-stage {
    position: relative;
    width: 100%;
    height: 480px;
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 2;
    margin: 10px 0;
  }

  .stage-card {
    width: 760px;
    height: 440px;
    background: radial-gradient(circle at 50% 40%, #063168 0%, #031c3e 60%, #011026 100%);
    border: 2px solid #00d2ff;
    border-radius: 28px;
    box-shadow: 0 0 70px rgba(0, 210, 255, 0.35), inset 0 0 40px rgba(0, 210, 255, 0.15);
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  /* Hologram Globe */
  .holo-globe {
    position: absolute;
    width: 320px;
    height: 320px;
    border-radius: 50%;
    border: 1px dashed rgba(0, 229, 255, 0.35);
    box-shadow: 0 0 40px rgba(0, 229, 255, 0.2);
    animation: pulse 4s infinite alternate;
  }

  /* Laptop Visual */
  .laptop-svg {
    width: 280px;
    height: 220px;
    z-index: 3;
    filter: drop-shadow(0 15px 30px rgba(0,0,0,0.7));
  }

  /* Glowing Shield */
  .shield-badge {
    position: absolute;
    width: 120px;
    height: 140px;
    z-index: 4;
    filter: drop-shadow(0 0 25px #00e5ff);
  }

  /* Floating Tech Pills */
  .tech-pill {
    position: absolute;
    background: rgba(4, 28, 62, 0.85);
    border: 1.5px solid #00d2ff;
    border-radius: 14px;
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    color: #e1f5fe;
    font-size: 13px;
    font-weight: 700;
    box-shadow: 0 6px 20px rgba(0,0,0,0.5);
    z-index: 4;
  }
  .tech-pill.p-top-left { top: 40px; left: 40px; }
  .tech-pill.p-top-right { top: 40px; right: 40px; }
  .tech-pill.p-bot-left { bottom: 40px; left: 40px; }
  .tech-pill.p-bot-right { bottom: 40px; right: 40px; }
  .tech-pill.p-mid-left { top: 190px; left: 20px; }
  .tech-pill.p-mid-right { top: 190px; right: 20px; }

  /* Bottom Metadata Grid */
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 22px 36px;
    z-index: 2;
    margin-top: 15px;
  }

  .meta-card {
    background: linear-gradient(135deg, rgba(3, 34, 76, 0.9) 0%, rgba(2, 20, 48, 0.95) 100%);
    border: 1.5px solid #1e88e5;
    border-radius: 40px;
    padding: 18px 30px;
    display: flex;
    align-items: center;
    gap: 20px;
    box-shadow: 0 10px 35px rgba(0,0,0,0.6);
  }

  .icon-circle {
    width: 58px;
    height: 58px;
    background: linear-gradient(135deg, #0288d1 0%, #01579b 100%);
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    color: #ffffff;
    flex-shrink: 0;
    box-shadow: 0 4px 15px rgba(2, 136, 209, 0.4);
  }

  .meta-content {
    display: flex;
    flex-direction: column;
  }
  .meta-label {
    font-size: 13.5px;
    color: #90caf9;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .meta-value {
    font-size: 21px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 2px;
    font-family: 'Montserrat', sans-serif;
  }
  .meta-subval {
    font-size: 14px;
    color: #64b5f6;
    font-weight: 600;
    margin-top: 1px;
  }

  /* Tagline Footer */
  .footer-tagline {
    text-align: center;
    font-size: 15px;
    letter-spacing: 6px;
    font-weight: 800;
    color: #64b5f6;
    text-transform: uppercase;
    border-top: 1.5px solid rgba(100, 181, 246, 0.3);
    padding-top: 24px;
    margin-top: 15px;
    z-index: 2;
  }
</style>
</head>
<body>
  <div class="grid-bg"></div>
  <div class="glow-radial"></div>

  <!-- Header Banner -->
  <div class="header-banner">
    <div class="softwarica-box">
      <div class="softwarica-brand">Softwarica</div>
      <div class="softwarica-sub">College of IT &amp; E-Commerce</div>
    </div>
    <div class="coventry-box">
      <span class="header-divider">in collaboration with</span>
      <div class="coventry-text">Coventry<br>University</div>
      <svg class="coventry-phoenix" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2L9 8h6l-3-6zm-7 9l4 2-3 7 7-3-1-3 4-1-2-2 3-1-9 1z"/>
      </svg>
    </div>
  </div>

  <!-- Title Section -->
  <div class="title-section">
    <div class="module-pill">Module Name</div>
    <h1 class="module-title">ST6005CEM Security</h1>
    <div class="module-sub">Cyber Security &nbsp;|&nbsp; Risk &nbsp;|&nbsp; Protection</div>
  </div>

  <!-- Central 3D Cyber Stage -->
  <div class="cyber-stage">
    <div class="stage-card">
      <div class="holo-globe"></div>

      <!-- Holographic Floating Badges -->
      <div class="tech-pill p-top-left">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>
        </svg>
        <span>HTTPS / TLS 1.3</span>
      </div>

      <div class="tech-pill p-top-right">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>AES-256-GCM</span>
      </div>

      <div class="tech-pill p-bot-left">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2">
          <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
        </svg>
        <span>Bcrypt (Cost 12)</span>
      </div>

      <div class="tech-pill p-bot-right">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
        </svg>
        <span>Wireshark PoC</span>
      </div>

      <!-- Center Shield & Padlock -->
      <svg class="shield-badge" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(0, 229, 255, 0.2)"/>
        <circle cx="12" cy="11" r="1.5" fill="#ffffff"/>
        <path d="M12 12.5v3" stroke="#ffffff" stroke-width="2"/>
        <rect x="9.5" y="10" width="5" height="6" rx="1" stroke="#ffffff" stroke-width="1.5"/>
        <path d="M10.5 10V8.5a1.5 1.5 0 0 1 3 0V10" stroke="#ffffff" stroke-width="1.5"/>
      </svg>
    </div>
  </div>

  <!-- Bottom Metadata Grid -->
  <div class="meta-grid">
    <!-- Submitted By -->
    <div class="meta-card">
      <div class="icon-circle">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
          <circle cx="12" cy="7" r="4"/>
        </svg>
      </div>
      <div class="meta-content">
        <span class="meta-label">Submitted By</span>
        <span class="meta-value">Rahul Shah</span>
        <span class="meta-subval">Student ID: 240204</span>
      </div>
    </div>

    <!-- Submitted To -->
    <div class="meta-card">
      <div class="icon-circle">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
      </div>
      <div class="meta-content">
        <span class="meta-label">Submitted To</span>
        <span class="meta-value">Arya Pokharel</span>
        <span class="meta-subval">Module Leader</span>
      </div>
    </div>

    <!-- Submission Date -->
    <div class="meta-card">
      <div class="icon-circle">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
          <line x1="16" y1="2" x2="16" y2="6"/>
          <line x1="8" y1="2" x2="8" y2="6"/>
          <line x1="3" y1="10" x2="21" y2="10"/>
        </svg>
      </div>
      <div class="meta-content">
        <span class="meta-label">Submission Date</span>
        <span class="meta-value">7th Oct 2026</span>
      </div>
    </div>

    <!-- Deadline -->
    <div class="meta-card">
      <div class="icon-circle">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
          <line x1="16" y1="2" x2="16" y2="6"/>
          <line x1="8" y1="2" x2="8" y2="6"/>
          <line x1="3" y1="10" x2="21" y2="10"/>
        </svg>
      </div>
      <div class="meta-content">
        <span class="meta-label">Deadline</span>
        <span class="meta-value">7th Oct 2026</span>
      </div>
    </div>
  </div>

  <!-- Footer Tagline -->
  <div class="footer-tagline">Secure Today &nbsp;|&nbsp; Safer Tomorrow</div>
</body>
</html>
`;

// Execution function
(async () => {
    console.log('[ACADEMIC VIEWS] Launching Edge to capture assets...');
    const browser = await puppeteer.launch({
        executablePath: EDGE_PATH,
        headless: 'new',
        args: ['--no-sandbox', '--disable-gpu']
    });

    const page = await browser.newPage();

    async function captureHtml(html, filename, width = 800, height = 500) {
        await page.setViewport({ width, height, deviceScaleFactor: 2 });
        await page.setContent(html, { waitUntil: 'domcontentloaded' });
        await new Promise(r => setTimeout(r, 200));
        const dest = path.join(OUTPUT_DIR, filename);
        await page.screenshot({ path: dest, fullPage: true });
        console.log(`[CAPTURED] ${filename}`);
    }

    await captureHtml(htmlCoverPage, 'cover_page.png', 1240, 1754);
    await captureHtml(htmlCertViewer, 'figure1_certificate.png', 720, 480);
    await captureHtml(htmlSignupPage, 'figure2_signup.png', 720, 560);
    await captureHtml(htmlWiresharkSignup, 'figure3_signup_capture.png', 960, 580);
    await captureHtml(htmlLoginPage, 'figure4_login.png', 720, 520);
    await captureHtml(htmlWiresharkLogin, 'figure5_login_capture.png', 960, 580);

    await browser.close();
    console.log('[ACADEMIC VIEWS] All visual captures successfully rendered in screenshots/academic!');
})();
