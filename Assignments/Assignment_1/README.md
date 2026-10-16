# Assignment 1: Secure File Upload

**Module:** WEB404 Secure Coding Practices
**Task:** Build a file upload feature and add security measures that stop malicious files from being uploaded.

---

## 1. Introduction

File upload is one of the riskiest features in a web application. If uploads are not handled carefully, an attacker can:

- upload a **web shell** (e.g. `shell.php`) and run commands on the server (Remote Code Execution),
- upload **HTML/SVG files containing JavaScript** that run in other users' browsers (Stored XSS),
- use **path traversal** file names (`../../server.js`) to overwrite application files,
- send **huge or very many files** to fill the disk and crash the service (Denial of Service),
- hide malicious code inside an otherwise valid image (**polyglot files**).

OWASP lists "Unrestricted File Upload" as a serious vulnerability. This project builds a working upload feature in **Node.js + Express** and protects it with several independent layers of defence (defence in depth), so getting past one check is not enough to compromise the system.

## 2. Technologies Used

| Component | Technology |
|-----------|------------|
| Runtime | Node.js (v20+) |
| Web framework | Express 5 |
| Multipart parsing | Multer 2 (memory storage) |
| Frontend | HTML, CSS, vanilla JavaScript |
| Testing | Node.js built-in test runner (`node:test`) |

## 3. Project Structure

```
Assignment_1/
├── public/                  # Frontend (the only folder served statically)
│   ├── index.html
│   ├── app.js
│   └── style.css
├── src/
│   ├── server.js            # Express app, routes, error handling
│   ├── config.js            # Limits and paths
│   ├── storage.js           # Saves files with random names, outside web root
│   ├── middleware/
│   │   └── security.js      # Security headers, rate limiter, CSRF origin check
│   └── validators/
│       └── fileValidator.js # File validation pipeline
├── test/
│   └── upload.test.js       # 26 automated attack/security tests
├── uploads/                 # Created at runtime (git-ignored)
└── logs/security.log        # Created at runtime (git-ignored)
```

## 4. How to Run

```bash
npm install
npm start          # open http://localhost:3000
npm test           # runs the security test suite
```

## 5. Features

- Upload a file by clicking or dragging and dropping it
- See a list of uploaded files (name, type, size, date)
- Download uploaded files
- Clear success and error messages

**Allowed file types:** PNG, JPG/JPEG, GIF, PDF. **Maximum size:** 5 MB, one file per request.

## 6. Security Measures Implemented

### Upload request flow

```
Browser ──► Security headers ──► CSRF origin check ──► Rate limiter
        ──► Multer (size / count limits, held in memory only)
        ──► Validation pipeline:
              1. File name checks (length, control chars, traversal)
              2. Double-extension check
              3. Extension allow-list
              4. Size check (not empty, ≤ 5 MB)
              5. MIME type must match extension
              6. Magic bytes must match extension
              7. File trailer / structure check
              8. Malicious content scan
        ──► Saved with a random UUID name outside the web root
        ──► Security event logged
```

### 6.1 Extension allow-list (not a block-list)
Only `png, jpg, jpeg, gif, pdf` are accepted (`fileValidator.js`). A block-list is always incomplete (`.php5`, `.phtml`, `.phar` …), so an allow-list is safer.

### 6.2 Double-extension and null-byte protection
Names like `shell.php.jpg` are rejected when any inner extension is executable (php, asp, jsp, exe, html, svg, …), because a badly configured Apache server may still run them as PHP. Names with null bytes or control characters (`shell.php\0.png`) are rejected, which blocks truncation attacks.

### 6.3 Magic-byte (file signature) verification
The browser's `Content-Type` and the file extension are both controlled by the user, so the server reads the **first bytes of the file** to confirm what it really is:

| Type | Signature |
|------|-----------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| GIF | `GIF87a` / `GIF89a` |
| PDF | `%PDF-` |

A PHP script renamed to `cat.jpg` fails this check.

### 6.4 MIME type consistency
The declared MIME type must match the extension. A PNG sent as `text/html` is rejected.

### 6.5 Structure (trailer) check: stops appended payloads
Valid files end in a known way (PNG ends with an `IEND` chunk, JPEG with `FF D9`, GIF with `0x3B`, PDF with `%%EOF`). Attackers often **append** a script to a real image to make a polyglot. This check catches that.

### 6.6 Malicious content scanning
The file bytes are scanned for signatures that should never appear in an image or PDF: `<?php`, `<?=`, `<script`, `<html`, `<iframe`, JSP/ASP directives, shebangs (`#!/`), `javascript:` URIs, and PDF active content (`/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`).

### 6.7 Validate in memory before writing to disk
Multer uses **memory storage**, so the file is held in RAM and only written to disk **after** it passes every check. A malicious file never touches the file system.

### 6.8 Random server-generated file names
Files are stored as `<UUID>.<ext>` (e.g. `3f2b…e9.png`) using `crypto.randomUUID()`. The user's file name is **never used to build a path**. This prevents:
- path traversal (`../../server.js`),
- overwriting other files (`wx` flag fails if the file exists),
- guessing other users' file names.

The original name is sanitised and kept **only for display**. `resolveSafe()` also checks that every resolved path stays inside the upload folder.

### 6.9 Storage outside the web root
Only `public/` is served statically. `uploads/` is outside it, so an uploaded file can never be requested directly by URL or executed by the web server. Files are written with mode `0640` (not executable).

### 6.10 Safe download endpoint
`GET /api/files/:id`:
- the id must match a strict UUID regex, so `../../package.json` gets **400**,
- the file is looked up in the index, never built from user input,
- `Content-Disposition: attachment` forces a download instead of rendering in the browser,
- `Content-Type` is the **server-verified** type, not what the user sent,
- `X-Content-Type-Options: nosniff` and a `sandbox` CSP stop the browser from treating the file as HTML/script.

### 6.11 Size and count limits (DoS protection)
Multer enforces a 5 MB limit **while streaming**, so oversized uploads are cut off early (HTTP 413). It also limits to 1 file and a small number of form fields/parts per request.

### 6.12 Rate limiting
A maximum of 20 uploads per IP every 15 minutes (`security.js`). Further requests get **HTTP 429** with a `Retry-After` header. This prevents upload flooding and disk exhaustion.

### 6.13 CSRF protection
Upload requests whose `Origin` header does not match the server are rejected with **403**, so a malicious website cannot make a logged-in user's browser upload files.

### 6.14 Security headers
Every response includes:
- `Content-Security-Policy` (no inline scripts, no plugins, no framing),
- `X-Content-Type-Options: nosniff`,
- `X-Frame-Options: DENY` (clickjacking),
- `Referrer-Policy: no-referrer`,
- `Cross-Origin-Resource-Policy: same-origin`,
- `X-Powered-By` removed (hides the technology stack).

### 6.15 XSS-safe frontend
The frontend only uses `textContent` (never `innerHTML`) to show file names and messages, so a file named `<img src=x onerror=alert(1)>.png` is shown as plain text. Client-side checks exist **only for user experience**. The server re-checks everything.

### 6.16 Secure error handling and logging
- Clients get short, generic error messages. Stack traces and internal paths are never shown.
- Every accepted and rejected upload is logged to `logs/security.log` as JSON (time, IP, reason, SHA-256 hash). This supports incident investigation.

Example log entries:
```json
{"time":"2026-10-10T06:12:01.112Z","event":"upload-rejected","ip":"::1","reason":"double-extension","name":"shell.php.jpg"}
{"time":"2026-10-10T06:12:05.448Z","event":"upload-accepted","ip":"::1","id":"9b1c…","sha256":"e3b0…"}
```

## 7. Threat → Defence Mapping

| Attack | Example | Defence(s) | Result |
|--------|---------|------------|--------|
| Web shell upload | `shell.php` | Extension allow-list | 400 |
| Double extension | `shell.php.jpg` | Double-extension check | 400 |
| Disguised script | PHP code saved as `cat.jpg` | Magic bytes | 400 |
| Polyglot image | valid PNG + PHP appended | Trailer check + content scan | 400 |
| MIME spoofing | PNG sent as `text/html` | MIME/extension match | 400 |
| Stored XSS | `logo.svg`, `page.html` with `<script>` | Allow-list, content scan, nosniff, attachment | 400 |
| Malicious PDF | PDF with `/JavaScript` | PDF active-content scan | 400 |
| Null byte | `shell.php\0.png` | Control-character check / parser | 400 |
| Server config override | `.htaccess` | Allow-list | 400 |
| Path traversal (upload) | `../../../evil.png` | Path stripped, UUID name, `resolveSafe()` | Stored safely |
| Path traversal (download) | `/api/files/../../package.json` | UUID regex | 400 |
| Direct execution | `/uploads/x.php` | Storage outside web root | 404 |
| Large file DoS | 6 MB file | Multer size limit | 413 |
| Upload flooding | many requests | Rate limiter | 429 |
| CSRF | upload from `evil.example` | Origin check | 403 |
| Clickjacking | framing the page | `X-Frame-Options`, CSP | Blocked |

This maps to the **OWASP File Upload Cheat Sheet** recommendations and to OWASP Top 10 categories **A01 Broken Access Control** (path traversal), **A03 Injection** (XSS / code execution), **A05 Security Misconfiguration** (headers, storage location) and **A09 Security Logging and Monitoring Failures** (logging).

## 8. Testing

The test suite (`test/upload.test.js`) starts the server and sends real attack payloads to it.

```
$ npm test
✔ accepts a valid PNG image
✔ accepts a valid JPEG image
✔ accepts a valid PDF document
✔ rejects a PHP script (.php)
✔ rejects an executable (.exe)
✔ rejects double extension (shell.php.jpg)
✔ rejects a PHP script renamed to .jpg (magic bytes check)
✔ rejects a polyglot PNG with PHP code appended
✔ rejects a PNG with PHP code hidden inside
✔ rejects MIME type spoofing (PNG sent as text/html)
✔ rejects SVG files carrying JavaScript (stored XSS)
✔ rejects HTML files (stored XSS)
✔ rejects a PDF containing JavaScript
✔ rejects null byte injection (shell.php\0.png)
✔ rejects .htaccess upload
✔ rejects empty files
✔ rejects files larger than 5 MB (413)
✔ rejects multiple files in one request
✔ path traversal in file name never escapes the upload folder
✔ rejects cross-origin upload (CSRF)
✔ stored files get random names, not the user-supplied name
✔ downloads are forced as attachments with nosniff
✔ download endpoint rejects traversal / invalid ids
✔ uploaded files are not reachable as static files
✔ security headers are set
✔ rate limiting blocks upload flooding (429)
ℹ tests 26
ℹ pass 26
ℹ fail 0
```

### Manual testing with curl

```bash
# Valid upload
curl -F "file=@photo.png;type=image/png" http://localhost:3000/api/upload

# Web shell: rejected
curl -F "file=@shell.php" http://localhost:3000/api/upload
# {"error":"File type \".php\" is not allowed. Allowed: png, jpg, jpeg, gif, pdf."}

# Script disguised as an image: rejected
curl -F "file=@shell.php;filename=cat.jpg;type=image/jpeg" http://localhost:3000/api/upload
# {"error":"File content does not match its extension."}
```

> **Note:** While building this, Windows Defender quarantined the test file because it contained a real PHP web-shell string. The tests now use a harmless payload (`<?php echo "test-payload"; ?>`) that is assembled at runtime. This was a useful reminder that antivirus scanning is itself one layer of defence.

## 9. Limitations and Future Improvements

No single check is perfect. In a production system I would also add:

1. **Antivirus scanning** (e.g. ClamAV) of every file before storing it.
2. **Content Disarm & Reconstruction (CDR):** re-encode images with a library like `sharp`, which removes any hidden payload and metadata (EXIF/GPS). Compressed PDF streams can hide content from a simple pattern scan, so PDFs would be sanitised or converted.
3. **Authentication and authorisation:** at the moment any visitor can upload and download. Real apps should link files to user accounts and check ownership on download.
4. **Separate storage domain or object storage** (e.g. S3 with private buckets), so user content is never served from the main application's origin.
5. **Per-user storage quotas** and a persistent rate limiter (e.g. Redis) that works across multiple server instances.
6. **HTTPS and HSTS** in deployment.
7. A database instead of a JSON index file for metadata.

## 10. Conclusion

This assignment produced a working file upload feature that treats every part of an upload (name, extension, MIME type and content) as untrusted. Using several independent layers (allow-listing, signature verification, structure checks, content scanning, random storage names, storage outside the web root, safe download headers, size and rate limits, CSRF and security headers), the application blocks all 23 attack scenarios tested while still accepting legitimate files. The main lesson is **defence in depth**: each layer assumes the others might fail.

## References

- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- OWASP Top 10 (2021): https://owasp.org/Top10/
- Multer documentation: https://github.com/expressjs/multer
- List of file signatures: https://en.wikipedia.org/wiki/List_of_file_signatures
