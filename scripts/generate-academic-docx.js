/**
 * Generates the Academic Microsoft Word (.docx) report matching the exact Softwarica template:
 * - Cover page image / structure
 * - Table of Contents
 * - Table of Figures
 * - Certificate evidence with Figure 1 & Data Table
 * - Frontend Implementation (Signup page, Figure 2 & Wireshark capture Figure 3)
 * - Login page (Figure 4 & Wireshark capture Figure 5)
 * - Functional Test Results Table (11 tests)
 */

const fs = require('fs');
const path = require('path');
const {
    Document,
    Packer,
    Paragraph,
    TextRun,
    HeadingLevel,
    Table,
    TableRow,
    TableCell,
    WidthType,
    AlignmentType,
    ImageRun,
    BorderStyle
} = require('docx');

const ACADEMIC_DIR = path.join(__dirname, '../screenshots/academic');
const OUTPUT_DOCX = path.join(__dirname, '../Security_Implementation_Report.docx');

function loadImage(filename, width = 540, height = 340) {
    const fullPath = path.join(ACADEMIC_DIR, filename);
    if (!fs.existsSync(fullPath)) {
        console.warn(`[WARN] Image not found: ${fullPath}`);
        return null;
    }
    const data = fs.readFileSync(fullPath);
    return new ImageRun({
        data,
        transformation: { width, height }
    });
}

function createDocx() {
    console.log('[ACADEMIC DOCX] Compiling Microsoft Word (.docx) report...');

    const doc = new Document({
        styles: {
            default: {
                document: {
                    run: {
                        font: 'Times New Roman',
                        size: 24, // 12pt
                        color: '000000'
                    },
                    paragraph: {
                        spacing: { line: 360 } // 1.5 line spacing
                    }
                }
            }
        },
        sections: [
            // SECTION 1: COVER PAGE
            {
                properties: {
                    page: {
                        margin: { top: 720, bottom: 720, left: 720, right: 720 }
                    }
                },
                children: [
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            loadImage('cover_page.png', 560, 780)
                        ]
                    })
                ]
            },

            // SECTION 2: REPORT BODY
            {
                properties: {
                    page: {
                        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 }
                    }
                },
                children: [
                    // PAGE 2: TABLE OF CONTENTS
                    new Paragraph({
                        text: 'Table of Contents',
                        heading: HeadingLevel.TITLE,
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 200, after: 400 },
                        run: { bold: true, size: 32 }
                    }),
                    createTocRow('Certificate evidence', '4', true),
                    createTocRow('Frontend Implementation', '6', true),
                    createTocRow('    Signup page', '6', false),
                    createTocRow('    Login page', '8', false),
                    createTocRow('Functional Test Results', '10', true),

                    // PAGE 3: TABLE OF FIGURES
                    new Paragraph({
                        text: 'Table of Figures',
                        heading: HeadingLevel.TITLE,
                        alignment: AlignmentType.CENTER,
                        pageBreakBefore: true,
                        spacing: { before: 200, after: 400 },
                        run: { bold: true, size: 32 }
                    }),
                    createTocRow('Figure 1: Certificate', '4', true),
                    createTocRow('Figure 2:signup page', '6', true),
                    createTocRow('Figure 3: signup capture', '7', true),
                    createTocRow('Figure 4:Login Page', '8', true),
                    createTocRow('Figure 5: Login capture', '9', true),

                    // PAGE 4: CERTIFICATE EVIDENCE
                    new Paragraph({
                        text: 'Certificate evidence',
                        pageBreakBefore: true,
                        spacing: { before: 100, after: 200 },
                        run: { bold: true, size: 32 }
                    }),
                    new Paragraph({
                        text: 'Figure 1 shows the certificate presented by the server as seen in the browser Certificate Viewer.',
                        spacing: { after: 300 }
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [loadImage('figure1_certificate.png', 520, 340)]
                    }),
                    new Paragraph({
                        text: 'Figure 1: Certificate',
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 200 },
                        run: { bold: true, italics: true }
                    }),

                    // PAGE 5: CERTIFICATE TABLE
                    new Paragraph({
                        pageBreakBefore: true,
                        spacing: { before: 100 }
                    }),
                    createCertificateTable(),

                    // PAGE 6: FRONTEND IMPLEMENTATION - SIGNUP PAGE
                    new Paragraph({
                        text: 'Frontend Implementation',
                        pageBreakBefore: true,
                        spacing: { before: 100, after: 200 },
                        run: { bold: true, size: 32 }
                    }),
                    new Paragraph({
                        text: 'The frontend consists of a signup page and a login page. Both are loaded from https://localhost:3443 and submit to relative HTTPS endpoints, so the browser cannot downgrade to HTTP.',
                        spacing: { after: 250 }
                    }),
                    new Paragraph({
                        text: 'Signup page',
                        spacing: { before: 100, after: 150 },
                        run: { bold: true, size: 28 }
                    }),
                    new Paragraph({
                        text: 'The page collects username, email and password. The password field is masked and states the 12-character minimum. Invalid emails are rejected by the server.',
                        spacing: { after: 250 }
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [loadImage('figure2_signup.png', 480, 360)]
                    }),
                    new Paragraph({
                        text: 'Figure 2:signup page',
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 180 },
                        run: { bold: true, italics: true }
                    }),

                    // PAGE 7: SIGNUP CAPTURE
                    new Paragraph({
                        pageBreakBefore: true,
                        alignment: AlignmentType.CENTER,
                        children: [loadImage('figure3_signup_capture.png', 540, 340)]
                    }),
                    new Paragraph({
                        text: 'Figure 3: signup capture',
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 180 },
                        run: { bold: true, italics: true }
                    }),

                    // PAGE 8: LOGIN PAGE
                    new Paragraph({
                        text: 'Login page',
                        pageBreakBefore: true,
                        spacing: { before: 100, after: 150 },
                        run: { bold: true, size: 28 }
                    }),
                    new Paragraph({
                        text: 'The login page accepts a username or the registered email together with the password and submits them to /api/login.',
                        spacing: { after: 250 }
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [loadImage('figure4_login.png', 480, 360)]
                    }),
                    new Paragraph({
                        text: 'Figure 4:Login Page',
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 180 },
                        run: { bold: true, italics: true }
                    }),

                    // PAGE 9: LOGIN CAPTURE
                    new Paragraph({
                        pageBreakBefore: true,
                        alignment: AlignmentType.CENTER,
                        children: [loadImage('figure5_login_capture.png', 540, 340)]
                    }),
                    new Paragraph({
                        text: 'Figure 5: Login capture',
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 180 },
                        run: { bold: true, italics: true }
                    }),

                    // PAGE 10: FUNCTIONAL TEST RESULTS
                    new Paragraph({
                        text: 'Functional Test Results',
                        pageBreakBefore: true,
                        spacing: { before: 100, after: 200 },
                        run: { bold: true, size: 32 }
                    }),
                    new Paragraph({
                        text: 'The authentication flow was exercised with HTTPS requests to https://localhost:3443. Every case produced the expected result.',
                        spacing: { after: 250 }
                    }),
                    createFunctionalTestsTable()
                ]
            }
        ]
    });

    Packer.toBuffer(doc).then(buffer => {
        fs.writeFileSync(OUTPUT_DOCX, buffer);
        console.log(`[ACADEMIC DOCX] Success! Word document written to: ${OUTPUT_DOCX} (${buffer.length} bytes)`);
    });
}

function createTocRow(title, pageNum, isBold) {
    return new Paragraph({
        spacing: { after: 140 },
        children: [
            new TextRun({ text: title, bold: isBold }),
            new TextRun({ text: ' ................................................................................................................... ' }),
            new TextRun({ text: pageNum, bold: isBold })
        ]
    });
}

function createCertificateTable() {
    const rows = [
        ['Common Name (CN)', 'localhost'],
        ['Issued by', 'localhost (self-signed)'],
        ['Valid from', 'Wednesday, 7 October 2026, 8:41:20 AM'],
        ['Valid until', 'Tuesday, 9 January 2029, 8:41:20 AM'],
        ['SHA-256 fingerprint (certificate)', '636137f0c96454f35e532ad477c5eb97ae53c1fc408a8fd12e09725f1ca96fc6'],
        ['SHA-256 fingerprint (public key)', 'cae2e8fc1d0582da70ee1b6b1fcc1e3f24c5465b8161171eee5d5e892613f76f']
    ];

    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
            new TableRow({
                children: [
                    new TableCell({
                        width: { size: 35, type: WidthType.PERCENTAGE },
                        children: [new Paragraph({ children: [new TextRun({ text: 'Field', bold: true })] })]
                    }),
                    new TableCell({
                        width: { size: 65, type: WidthType.PERCENTAGE },
                        children: [new Paragraph({ children: [new TextRun({ text: 'Value', bold: true })] })]
                    })
                ]
            }),
            ...rows.map(([field, val]) =>
                new TableRow({
                    children: [
                        new TableCell({ children: [new Paragraph(field)] }),
                        new TableCell({ children: [new Paragraph(val)] })
                    ]
                })
            )
        ]
    });
}

function createFunctionalTestsTable() {
    const testCases = [
        ['1', 'Signup with invalid email "not-an-email"', 'Rejected', '400: A valid email address is required'],
        ['2', 'Signup with 5-character password', 'Rejected', '400: Password must be at least 12 characters'],
        ['3', 'Signup with valid data', 'Account created', '201: Account created'],
        ['4', 'Signup again with same username and email', 'Rejected', '409: Username or email already registered'],
        ['5', 'Login with wrong password', 'Rejected', '401: Invalid credentials'],
        ['6', 'Login with username and correct password', 'Success, cookie set', '200: Login successful; cookie HttpOnly, Secure, SameSite=Strict'],
        ['7', 'Login with email (different letter case)', 'Success', '200: Login successful (blind index match)'],
        ['8', 'Read profile with session cookie', 'Email decrypted for owner', '200: student01, student@example.com'],
        ['9', 'Read profile without cookie', 'Denied', '401: Not authenticated'],
        ['10', 'Plain HTTP request to port 3443', 'No response', 'Connection fails (HTTP code 000)'],
        ['11', 'TLS negotiation', 'TLS 1.3', 'TLSv1.3, TLS_AES_256_GCM_SHA384, X25519, certificate verified']
    ];

    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
            new TableRow({
                children: [
                    new TableCell({ width: { size: 8, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: '#', bold: true })] })] }),
                    new TableCell({ width: { size: 36, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: 'Test', bold: true })] })] }),
                    new TableCell({ width: { size: 24, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: 'Expected', bold: true })] })] }),
                    new TableCell({ width: { size: 32, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: 'Result', bold: true })] })] })
                ]
            }),
            ...testCases.map(([num, test, exp, res]) =>
                new TableRow({
                    children: [
                        new TableCell({ children: [new Paragraph(num)] }),
                        new TableCell({ children: [new Paragraph(test)] }),
                        new TableCell({ children: [new Paragraph(exp)] }),
                        new TableCell({ children: [new Paragraph(res)] })
                    ]
                })
            )
        ]
    });
}

createDocx();
