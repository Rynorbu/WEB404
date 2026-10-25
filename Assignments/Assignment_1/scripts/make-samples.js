/**
 * Generates sample files (safe and malicious) for demonstrating the upload
 * defences and taking report screenshots.  Run with: npm run samples
 *
 * The "malicious" payloads are HARMLESS stand-ins (e.g. PHP that only echoes
 * text) - they imitate the structure of real attacks without doing damage.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT = path.join(__dirname, '..', 'samples');
fs.mkdirSync(OUT, { recursive: true });

// ---------------------------------------------------------------- helpers
function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) {
    crc ^= byte;
    for (let k = 0; k < 8; k++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Builds a real, viewable PNG (greyscale shield-like pattern). */
function makePng(width, height) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: RGB
  const rows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 3);
    for (let x = 0; x < width; x++) {
      const cx = x - width / 2, cy = y - height / 2;
      const ring = Math.floor(Math.sqrt(cx * cx + cy * cy) / 12) % 2;
      const v = ring ? 40 : 200 - Math.floor((y / height) * 120);
      row.fill(v, 1 + x * 3, 4 + x * 3);
    }
    rows.push(row);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(Buffer.concat(rows))),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Builds a real, openable one-page PDF with a correct xref table. */
function makePdf(text, extraCatalog = '') {
  const content = `BT /F1 28 Tf 72 720 Td (${text}) Tj ET\nBT /F1 12 Tf 72 690 Td (WEB404 Secure Coding - Assignment 1 sample file) Tj ET`;
  const objects = [
    `<< /Type /Catalog /Pages 2 0 R ${extraCatalog}>>`,
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((obj, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, 'latin1');
}

// Built from pieces so antivirus software does not flag this script.
const php = ['<', '?php', ' echo "Harmless test payload - this would be a web shell"; ?>'].join('');
const png = makePng(320, 200);
const jpgStub = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64, 7), Buffer.from([0xff, 0xd9])]);

const samples = [
  // name, contents, description
  ['01-valid-image.png', png, 'Legitimate PNG image - should be ACCEPTED'],
  ['02-valid-document.pdf', makePdf('Sample Document'), 'Legitimate PDF - should be ACCEPTED'],
  ['03-shell.php', php, 'PHP web shell - blocked by extension allow-list'],
  ['04-shell.php.jpg', jpgStub, 'Double extension - blocked by double-extension check'],
  ['05-fake-image.jpg', php, 'PHP script renamed to .jpg - blocked by magic-byte check'],
  ['06-polyglot.png', Buffer.concat([png, Buffer.from(php)]), 'Real PNG with PHP appended - blocked by trailer check'],
  ['07-xss.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>', 'SVG with JavaScript - blocked (stored XSS)'],
  ['08-page.html', '<html><body><script>alert("XSS")</script></body></html>', 'HTML file - blocked (stored XSS)'],
  ['09-malicious.pdf', makePdf('Invoice', '/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> '), 'PDF with JavaScript - blocked by content scan'],
  ['10-setup.exe', Buffer.from('MZ\x90\x00\x03\x00\x00\x00 harmless stub', 'latin1'), 'Windows executable - blocked by allow-list'],
  ['11-large-file.png', Buffer.concat([png.subarray(0, -12), Buffer.alloc(6 * 1024 * 1024), png.subarray(-12)]), '6 MB file - blocked by size limit (413)'],
  ['12-empty.png', Buffer.alloc(0), 'Empty file - blocked'],
];

for (const [name, data] of samples) fs.writeFileSync(path.join(OUT, name), data);

console.log(`Created ${samples.length} sample files in ${OUT}\n`);
for (const [name, , desc] of samples) console.log(`  ${name.padEnd(24)} ${desc}`);
console.log('\nNote: if antivirus software deletes 03, 05 or 06, that is expected - re-run or add an exclusion for the samples folder.');
