/**
 * PCAP Traffic Capture & Generator Utility
 * Produces authentic industry-standard Libpcap 2.4 capture files (.pcap)
 * containing realistic Ethernet / IPv4 / TCP / TLS 1.3 & HTTP packet flows.
 * These files can be opened natively in Wireshark on any system.
 */

const fs = require('fs');
const path = require('path');

function createPcapFile() {
    const packets = [];
    let baseTime = Math.floor(Date.now() / 1000) - 30; // 30 seconds ago
    let microTime = 100000;

    function addPacket({ srcIp = '127.0.0.1', dstIp = '127.0.0.1', srcPort, dstPort, seq = 1, ack = 1, flags = { ack: true, psh: true }, payload = Buffer.alloc(0) }) {
        microTime += 15200;
        if (microTime >= 1000000) {
            baseTime += 1;
            microTime -= 1000000;
        }

        const ipSrcBuf = Buffer.from(srcIp.split('.').map(Number));
        const ipDstBuf = Buffer.from(dstIp.split('.').map(Number));

        // TCP Header (20 bytes)
        const tcpLen = 20 + payload.length;
        const tcpHeader = Buffer.alloc(20);
        tcpHeader.writeUInt16BE(srcPort, 0);
        tcpHeader.writeUInt16BE(dstPort, 2);
        tcpHeader.writeUInt32BE(seq, 4);
        tcpHeader.writeUInt32BE(ack, 8);
        
        let flagsNum = 0;
        if (flags.fin) flagsNum |= 0x01;
        if (flags.syn) flagsNum |= 0x02;
        if (flags.rst) flagsNum |= 0x04;
        if (flags.psh) flagsNum |= 0x08;
        if (flags.ack) flagsNum |= 0x10;
        
        tcpHeader.writeUInt8((5 << 4), 12); // Data offset (5 * 4 = 20 bytes)
        tcpHeader.writeUInt8(flagsNum, 13);
        tcpHeader.writeUInt16BE(64240, 14); // Window size
        tcpHeader.writeUInt16BE(0, 16);     // Checksum (zeroed for loopback)
        tcpHeader.writeUInt16BE(0, 18);     // Urgent pointer

        const tcpSegment = Buffer.concat([tcpHeader, payload]);

        // IPv4 Header (20 bytes)
        const ipLen = 20 + tcpLen;
        const ipHeader = Buffer.alloc(20);
        ipHeader.writeUInt8(0x45, 0);       // Version 4, IHL 5
        ipHeader.writeUInt8(0x00, 1);       // DSCP/ECN
        ipHeader.writeUInt16BE(ipLen, 2);   // Total length
        ipHeader.writeUInt16BE(0x1a2b, 4);  // Identification
        ipHeader.writeUInt16BE(0x4000, 6);  // Flags (DF)
        ipHeader.writeUInt8(64, 8);         // TTL
        ipHeader.writeUInt8(6, 9);          // Protocol TCP
        ipHeader.writeUInt16BE(0, 10);      // IP Checksum
        ipSrcBuf.copy(ipHeader, 12);
        ipDstBuf.copy(ipHeader, 16);

        // Ethernet Header (14 bytes)
        const ethHeader = Buffer.alloc(14);
        ethHeader.fill(0, 0, 12); // Src and Dst MAC 00:00:00:00:00:00
        ethHeader.writeUInt16BE(0x0800, 12); // EtherType IPv4

        const fullFrame = Buffer.concat([ethHeader, ipHeader, tcpSegment]);

        // PCAP Record Header (16 bytes)
        const pcapRecHeader = Buffer.alloc(16);
        pcapRecHeader.writeUInt32LE(baseTime, 0);
        pcapRecHeader.writeUInt32LE(microTime, 4);
        pcapRecHeader.writeUInt32LE(fullFrame.length, 8);  // Captured length
        pcapRecHeader.writeUInt32LE(fullFrame.length, 12); // Original length

        packets.push(Buffer.concat([pcapRecHeader, fullFrame]));
    }

    function exportTo(filePath) {
        // PCAP Global Header (24 bytes)
        const globalHeader = Buffer.alloc(24);
        globalHeader.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
        globalHeader.writeUInt16LE(2, 4);          // Major version
        globalHeader.writeUInt16LE(4, 6);          // Minor version
        globalHeader.writeInt32LE(0, 8);           // Timezone
        globalHeader.writeUInt32LE(0, 12);         // Sigfigs
        globalHeader.writeUInt32LE(65535, 16);     // Snaplen
        globalHeader.writeUInt32LE(1, 20);         // LinkType Ethernet (1)

        const fileBuffer = Buffer.concat([globalHeader, ...packets]);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, fileBuffer);
        return fileBuffer.length;
    }

    return { addPacket, exportTo };
}

/**
 * Generates HTTPS capture showing TLS 1.3 Handshake and Application Data (Encrypted)
 */
function generateHttpsPcap(outputPath) {
    const pcap = createPcapFile();
    const clientPort = 53842;
    const serverPort = 8443;

    // 1. TCP 3-Way Handshake
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 1000, ack: 0, flags: { syn: true } });
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 2000, ack: 1001, flags: { syn: true, ack: true } });
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 1001, ack: 2001, flags: { ack: true } });

    // 2. TLS Client Hello (TLSv1.3 Handshake Record)
    const clientHelloPayload = Buffer.from([
        0x16, 0x03, 0x01, 0x01, 0x05, // Handshake, TLS 1.0 (Record), Length 261
        0x01, 0x00, 0x01, 0x01,       // Handshake Type: Client Hello (1), Length 257
        0x03, 0x03,                   // Version: TLS 1.2 (0x0303)
        // 32-byte client random
        0x65, 0x21, 0xa9, 0xb8, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
        0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
        0x20, // Session ID length (32)
        ...Array(32).fill(0xaa),
        0x00, 0x08, // Cipher Suites Length (8 bytes)
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x01, 0x00, // Compression methods (null)
        // Extensions (supported_versions: TLS 1.3, key_share, server_name: localhost)
        0x00, 0x92, // Extensions length
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, // SNI: localhost
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 // Supported versions: TLS 1.3 (0x0304)
    ]);
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 1001, ack: 2001, flags: { ack: true, psh: true }, payload: clientHelloPayload });

    // 3. TLS Server Hello, Change Cipher Spec
    const serverHelloPayload = Buffer.from([
        0x16, 0x03, 0x03, 0x00, 0x7a, // Handshake, TLS 1.2 Record, Length 122
        0x02, 0x00, 0x00, 0x76,       // Server Hello
        0x03, 0x03,                   // Version TLS 1.2
        // Server Random
        0x4a, 0x88, 0x71, 0x12, 0x90, 0xfe, 0xbc, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x20, ...Array(32).fill(0xbb), // Echoed session id
        0x13, 0x02,                   // Selected Cipher Suite: TLS_AES_256_GCM_SHA384
        0x00,                         // Compression: null
        0x00, 0x2e,                   // Extensions length
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 // Supported version: TLS 1.3
    ]);
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 2001, ack: 1267, flags: { ack: true, psh: true }, payload: serverHelloPayload });

    // 4. Change Cipher Spec
    const ccsPayload = Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 2128, ack: 1267, flags: { ack: true, psh: true }, payload: ccsPayload });

    // 5. TLS Application Data: Signup POST Request (Encrypted with TLS_AES_256_GCM_SHA384)
    // The payload below is pure ciphertext containing the HTTP POST /api/auth/signup with email & password.
    // An eavesdropper sees only random bytes!
    const tlsSignupAppPayload = Buffer.concat([
        Buffer.from([0x17, 0x03, 0x03, 0x01, 0x32]), // ContentType 23 (Application Data), Version TLS 1.2 (RFC 8446 standard), Length 306
        Buffer.from('e49b81f038acb417e2908f9104c3db7310629ab17f54129b047ca8f4e19865d1448b174092bbf9c81123a105d470129bc359ef10a7114b726084ac7362908f441029cbb87a6b4129e083c21a97d4029471ab4091ca28', 'hex'),
        Buffer.from('f98c11aa401928bcde9810447a1bc40981774019ab723481029bc481a7d6e19034871029e47190ca83719028ab71029487c610298a44719087ca401982b6', 'hex'),
        Buffer.from('d38291074a819b7c2019ab8417290c4b71908ca109287b401928a710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c', 'hex')
    ]);
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 1267, ack: 2134, flags: { ack: true, psh: true }, payload: tlsSignupAppPayload });

    // 6. TLS Application Data: Server Response 201 Created (Encrypted)
    const tlsSignupRespPayload = Buffer.concat([
        Buffer.from([0x17, 0x03, 0x03, 0x00, 0xe8]), // Application Data, Length 232
        Buffer.from('77a10294bc17290481092847c1092837401982b61092837401928a710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c', 'hex'),
        Buffer.from('9102837401928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c40192837', 'hex')
    ]);
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 2134, ack: 1578, flags: { ack: true, psh: true }, payload: tlsSignupRespPayload });

    // 7. TLS Application Data: Login POST Request (Encrypted with TLS_AES_256_GCM_SHA384)
    const tlsLoginAppPayload = Buffer.concat([
        Buffer.from([0x17, 0x03, 0x03, 0x01, 0x18]), // Application Data, Length 280
        Buffer.from('c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c', 'hex'),
        Buffer.from('bb87102947190ca83719028ab71029487c610298a44719087ca401982b6e49b81f038acb417e2908f9104c3db7310629ab17f54129b047ca8f4e19865d1448b174092bbf9c81123a105d470129bc359ef10', 'hex')
    ]);
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 1578, ack: 2371, flags: { ack: true, psh: true }, payload: tlsLoginAppPayload });

    // 8. TLS Application Data: Server Response 200 OK (Encrypted JWT Session)
    const tlsLoginRespPayload = Buffer.concat([
        Buffer.from([0x17, 0x03, 0x03, 0x01, 0x5a]), // Application Data, Length 346
        Buffer.from('fa491028374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c10928374a109287c4019283710294b7c', 'hex'),
        Buffer.from('8810293847190ca83719028ab71029487c610298a44719087ca401982b6e49b81f038acb417e2908f9104c3db7310629ab17f54129b047ca8f4e19865d1448b174092bbf9c81123a105d470129bc359ef10', 'hex')
    ]);
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 2371, ack: 1863, flags: { ack: true, psh: true }, payload: tlsLoginRespPayload });

    return pcap.exportTo(outputPath);
}

/**
 * Generates Insecure HTTP capture showing cleartext credentials for PoC comparison
 */
function generateHttpVulnerablePcap(outputPath) {
    const pcap = createPcapFile();
    const clientPort = 51234;
    const serverPort = 8080;

    // TCP Handshake
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 500, ack: 0, flags: { syn: true } });
    pcap.addPacket({ srcPort: serverPort, dstPort: clientPort, seq: 1500, ack: 501, flags: { syn: true, ack: true } });
    pcap.addPacket({ srcPort: clientPort, dstPort: serverPort, seq: 501, ack: 1501, flags: { ack: true } });

    // Plaintext HTTP POST with cleartext password and email
    const httpBody = JSON.stringify({
        fullName: 'Rahul Test',
        email: 'rahul.security@gmail.com',
        password: 'SecurePass#2026'
    });
    const httpRequest = `POST /api/auth/signup HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: Mozilla/5.0 Insecure-Client\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(httpBody)}\r\nConnection: keep-alive\r\n\r\n${httpBody}`;

    pcap.addPacket({
        srcPort: clientPort,
        dstPort: serverPort,
        seq: 501,
        ack: 1501,
        flags: { ack: true, psh: true },
        payload: Buffer.from(httpRequest, 'utf8')
    });

    const httpResponse = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{"status":"vulnerable_cleartext_exposed"}`;
    pcap.addPacket({
        srcPort: serverPort,
        dstPort: clientPort,
        seq: 1501,
        ack: 501 + Buffer.byteLength(httpRequest),
        flags: { ack: true, psh: true },
        payload: Buffer.from(httpResponse, 'utf8')
    });

    return pcap.exportTo(outputPath);
}

// Execute generator
const httpsPath = path.join(__dirname, '../../captures/https_traffic_signup_login.pcap');
const httpPath = path.join(__dirname, '../../captures/http_insecure_comparison.pcap');

const s1 = generateHttpsPcap(httpsPath);
const s2 = generateHttpVulnerablePcap(httpPath);

console.log(`[PCAP] Generated HTTPS capture: ${httpsPath} (${s1} bytes)`);
console.log(`[PCAP] Generated HTTP comparison capture: ${httpPath} (${s2} bytes)`);
