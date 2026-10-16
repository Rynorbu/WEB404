/**
 * Security tests: each test simulates a real malicious-upload technique and
 * checks that the server blocks it. Run with: npm test
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApp } = require('../src/server');

// ---- Sample files built in memory ------------------------------------------
const PNG_HEADER = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_IEND = Buffer.from([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
const validPng = Buffer.concat([PNG_HEADER, Buffer.alloc(32, 1), PNG_IEND]);
const validJpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(32, 2), Buffer.from([0xff, 0xd9])]);
const validPdf = Buffer.from('%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n');
// Harmless stand-in for a PHP web shell. Built from pieces so antivirus
// software does not quarantine this test file.
const phpPayload = Buffer.from(['<', '?php', ' echo "test-payload"; ?>'].join(''));

let server, baseUrl, tmpDir;

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'upload-test-'));
  const app = createApp({
    uploadDir: path.join(tmpDir, 'uploads'),
    logDir: path.join(tmpDir, 'logs'),
    rateLimitMax: 1000,
  });
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function upload(buffer, filename, mime, { url = baseUrl, headers = {} } = {}) {
  const form = new FormData();
  form.append('file', new Blob([buffer], { type: mime }), filename);
  return fetch(`${url}/api/upload`, { method: 'POST', body: form, headers });
}

async function expectRejected(res, status = 400) {
  const body = await res.json();
  assert.strictEqual(res.status, status, `expected ${status}, got ${res.status}: ${JSON.stringify(body)}`);
  assert.ok(body.error);
  return body;
}

// ---- Legitimate uploads ------------------------------------------------------
test('accepts a valid PNG image', async () => {
  const res = await upload(validPng, 'photo.png', 'image/png');
  const body = await res.json();
  assert.strictEqual(res.status, 201);
  assert.match(body.file.id, /^[0-9a-f-]{36}$/);
});

test('accepts a valid JPEG image', async () => {
  const res = await upload(validJpg, 'holiday.photo.jpeg', 'image/jpeg');
  assert.strictEqual(res.status, 201);
});

test('accepts a valid PDF document', async () => {
  const res = await upload(validPdf, 'report.pdf', 'application/pdf');
  assert.strictEqual(res.status, 201);
});

// ---- Malicious uploads -------------------------------------------------------
test('rejects a PHP script (.php)', async () => {
  await expectRejected(await upload(phpPayload, 'shell.php', 'application/x-php'));
});

test('rejects an executable (.exe)', async () => {
  await expectRejected(await upload(Buffer.from('MZ\x90\x00'), 'setup.exe', 'application/octet-stream'));
});

test('rejects double extension (shell.php.jpg)', async () => {
  await expectRejected(await upload(validJpg, 'shell.php.jpg', 'image/jpeg'));
});

test('rejects a PHP script renamed to .jpg (magic bytes check)', async () => {
  await expectRejected(await upload(phpPayload, 'cat.jpg', 'image/jpeg'));
});

test('rejects a polyglot PNG with PHP code appended', async () => {
  const polyglot = Buffer.concat([validPng, phpPayload]);
  await expectRejected(await upload(polyglot, 'avatar.png', 'image/png'));
});

test('rejects a PNG with PHP code hidden inside', async () => {
  const hidden = Buffer.concat([PNG_HEADER, phpPayload, PNG_IEND]);
  await expectRejected(await upload(hidden, 'avatar.png', 'image/png'));
});

test('rejects MIME type spoofing (PNG sent as text/html)', async () => {
  await expectRejected(await upload(validPng, 'photo.png', 'text/html'));
});

test('rejects SVG files carrying JavaScript (stored XSS)', async () => {
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  await expectRejected(await upload(svg, 'logo.svg', 'image/svg+xml'));
});

test('rejects HTML files (stored XSS)', async () => {
  await expectRejected(await upload(Buffer.from('<html><script>alert(1)</script></html>'), 'page.html', 'text/html'));
});

test('rejects a PDF containing JavaScript', async () => {
  const evilPdf = Buffer.from('%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF\n');
  await expectRejected(await upload(evilPdf, 'invoice.pdf', 'application/pdf'));
});

test('rejects null byte injection (shell.php\\0.png)', async () => {
  await expectRejected(await upload(validPng, 'shell.php\u0000.png', 'image/png'));
});

test('rejects .htaccess upload', async () => {
  await expectRejected(await upload(Buffer.from('AddType application/x-httpd-php .png'), '.htaccess', 'text/plain'));
});

test('rejects empty files', async () => {
  await expectRejected(await upload(Buffer.alloc(0), 'empty.png', 'image/png'));
});

test('rejects files larger than 5 MB (413)', async () => {
  const big = Buffer.concat([PNG_HEADER, Buffer.alloc(5 * 1024 * 1024 + 10), PNG_IEND]);
  await expectRejected(await upload(big, 'huge.png', 'image/png'), 413);
});

test('rejects multiple files in one request', async () => {
  const form = new FormData();
  form.append('file', new Blob([validPng], { type: 'image/png' }), 'a.png');
  form.append('file', new Blob([validPng], { type: 'image/png' }), 'b.png');
  await expectRejected(await fetch(`${baseUrl}/api/upload`, { method: 'POST', body: form }));
});

test('path traversal in file name never escapes the upload folder', async () => {
  const res = await upload(validPng, '../../../evil.png', 'image/png');
  // Either rejected, or accepted with the path stripped and a random stored name
  if (res.status === 201) {
    const { file } = await res.json();
    assert.ok(!file.originalName.includes('/') && !file.originalName.includes('..'));
  } else {
    await expectRejected(res);
  }
  assert.ok(!fs.existsSync(path.join(tmpDir, 'evil.png')));
  assert.ok(!fs.existsSync(path.join(tmpDir, '..', 'evil.png')));
});

test('rejects cross-origin upload (CSRF)', async () => {
  const res = await upload(validPng, 'photo.png', 'image/png', { headers: { Origin: 'https://evil.example' } });
  await expectRejected(res, 403);
});

// ---- Storage & download -------------------------------------------------------
test('stored files get random names, not the user-supplied name', async () => {
  await upload(validPng, 'my-name.png', 'image/png');
  const stored = fs.readdirSync(path.join(tmpDir, 'uploads'));
  assert.ok(!stored.includes('my-name.png'));
  assert.ok(stored.some((f) => /^[0-9a-f-]{36}\.png$/.test(f)));
});

test('downloads are forced as attachments with nosniff', async () => {
  const res = await upload(validPng, 'photo.png', 'image/png');
  const { file } = await res.json();
  const dl = await fetch(`${baseUrl}/api/files/${file.id}`);
  assert.strictEqual(dl.status, 200);
  assert.strictEqual(dl.headers.get('x-content-type-options'), 'nosniff');
  assert.match(dl.headers.get('content-disposition'), /^attachment;/);
  assert.strictEqual(dl.headers.get('content-type'), 'image/png');
});

test('download endpoint rejects traversal / invalid ids', async () => {
  assert.strictEqual((await fetch(`${baseUrl}/api/files/..%2F..%2Fpackage.json`)).status, 400);
  assert.strictEqual((await fetch(`${baseUrl}/api/files/not-a-uuid`)).status, 400);
  assert.strictEqual((await fetch(`${baseUrl}/api/files/00000000-0000-4000-8000-000000000000`)).status, 404);
});

test('uploaded files are not reachable as static files', async () => {
  const stored = fs.readdirSync(path.join(tmpDir, 'uploads')).find((f) => f.endsWith('.png'));
  assert.strictEqual((await fetch(`${baseUrl}/uploads/${stored}`)).status, 404);
  assert.strictEqual((await fetch(`${baseUrl}/${stored}`)).status, 404);
});

test('security headers are set', async () => {
  const res = await fetch(baseUrl);
  assert.ok(res.headers.get('content-security-policy').includes("default-src 'self'"));
  assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
  assert.strictEqual(res.headers.get('x-powered-by'), null);
});

test('rate limiting blocks upload flooding (429)', async () => {
  const limitedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'upload-rl-'));
  const app = createApp({
    uploadDir: path.join(limitedDir, 'uploads'),
    logDir: path.join(limitedDir, 'logs'),
    rateLimitMax: 3,
  });
  const srv = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const url = `http://127.0.0.1:${srv.address().port}`;
  try {
    for (let i = 0; i < 3; i++) {
      assert.strictEqual((await upload(validPng, 'p.png', 'image/png', { url })).status, 201);
    }
    await expectRejected(await upload(validPng, 'p.png', 'image/png', { url }), 429);
  } finally {
    srv.close();
    fs.rmSync(limitedDir, { recursive: true, force: true });
  }
});
