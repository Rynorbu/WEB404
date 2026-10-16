/**
 * File validation pipeline.
 *
 * Every uploaded file must pass ALL of these checks (defence in depth).
 * Nothing the client sends (file name, extension, Content-Type) is trusted
 * on its own - the actual bytes are inspected.
 */

// ---------------------------------------------------------------------------
// 1. Allow-list of accepted file types
// ---------------------------------------------------------------------------
// Each type defines: accepted extensions, the expected MIME type, a "magic
// bytes" check for the start of the file and a trailer check for the end.
const ALLOWED_TYPES = {
  png: {
    extensions: ['png'],
    mime: 'image/png',
    // 89 50 4E 47 0D 0A 1A 0A
    header: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    // A PNG always ends with the IEND chunk (length 0 + "IEND" + CRC)
    trailer: (b) => b.subarray(-12).equals(Buffer.from([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82])),
  },
  jpg: {
    extensions: ['jpg', 'jpeg'],
    mime: 'image/jpeg',
    // FF D8 FF
    header: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
    // End Of Image marker FF D9
    trailer: (b) => b[b.length - 2] === 0xff && b[b.length - 1] === 0xd9,
  },
  gif: {
    extensions: ['gif'],
    mime: 'image/gif',
    header: (b) => ['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('latin1')),
    // GIF trailer byte 0x3B
    trailer: (b) => b[b.length - 1] === 0x3b,
  },
  pdf: {
    extensions: ['pdf'],
    mime: 'application/pdf',
    header: (b) => b.subarray(0, 5).toString('latin1') === '%PDF-',
    // "%%EOF" must appear near the end of the file
    trailer: (b) => b.subarray(-1024).toString('latin1').includes('%%EOF'),
  },
};

const EXTENSION_TO_TYPE = {};
for (const [type, def] of Object.entries(ALLOWED_TYPES)) {
  for (const ext of def.extensions) EXTENSION_TO_TYPE[ext] = type;
}

// ---------------------------------------------------------------------------
// 2. Executable / dangerous extensions, used to catch double extensions such
//    as "shell.php.jpg" which some misconfigured servers will execute.
// ---------------------------------------------------------------------------
const DANGEROUS_EXTENSIONS = new Set([
  'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'pht',
  'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'cer', 'jsp', 'jspx', 'jsf',
  'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'ps1', 'psm1', 'bat', 'cmd', 'com',
  'exe', 'dll', 'msi', 'scr', 'vbs', 'vbe', 'js', 'mjs', 'jar', 'war',
  'html', 'htm', 'xhtml', 'shtml', 'svg', 'xml', 'swf', 'hta', 'htaccess',
]);

// ---------------------------------------------------------------------------
// 3. Content signatures that should never appear inside an image or PDF.
//    These catch polyglot files, e.g. a valid PNG with PHP code appended.
// ---------------------------------------------------------------------------
const MALICIOUS_PATTERNS = [
  { name: 'PHP code', regex: /<\?php/i },
  { name: 'PHP short echo tag', regex: /<\?=/ },
  { name: 'Script tag', regex: /<script[\s>]/i },
  { name: 'HTML document', regex: /<html[\s>]/i },
  { name: 'Iframe tag', regex: /<iframe[\s>]/i },
  { name: 'JSP/ASP directive', regex: /<%@\s*(page|import|language)/i },
  { name: 'Shebang interpreter', regex: /^#!\s*\//m },
  { name: 'javascript: URI', regex: /javascript:/i },
  // PDF-specific active content
  { name: 'PDF JavaScript', regex: /\/JavaScript\b|\/JS\s*[(<]/ },
  { name: 'PDF launch action', regex: /\/Launch\b/ },
  { name: 'PDF embedded file', regex: /\/EmbeddedFile\b/ },
];

class ValidationError extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'ValidationError';
    this.reason = reason; // internal reason for the security log
  }
}

/**
 * Validates the original file name supplied by the client.
 * Returns the lower-case final extension.
 */
function validateFilename(originalName, maxLength) {
  if (typeof originalName !== 'string' || originalName.length === 0) {
    throw new ValidationError('A file name is required.', 'empty-filename');
  }
  if (originalName.length > maxLength) {
    throw new ValidationError('File name is too long.', 'filename-too-long');
  }
  // Null bytes / control characters (e.g. "shell.php%00.jpg" truncation attack)
  if (/[\x00-\x1f\x7f]/.test(originalName)) {
    throw new ValidationError('File name contains invalid characters.', 'control-characters');
  }
  // Path traversal (e.g. "../../app/server.js")
  if (/[\\/]/.test(originalName) || originalName.includes('..')) {
    throw new ValidationError('File name contains invalid characters.', 'path-traversal');
  }

  const parts = originalName.toLowerCase().split('.');
  if (parts.length < 2 || parts[parts.length - 1] === '') {
    throw new ValidationError('File must have an extension.', 'no-extension');
  }

  const ext = parts[parts.length - 1].trim();
  // Any dangerous extension anywhere in the name (double extension attack)
  const inner = parts.slice(1, -1).map((p) => p.trim());
  if (inner.some((p) => DANGEROUS_EXTENSIONS.has(p))) {
    throw new ValidationError('File name has a disallowed double extension.', 'double-extension');
  }
  if (!EXTENSION_TO_TYPE[ext]) {
    throw new ValidationError(
      `File type ".${ext}" is not allowed. Allowed: ${Object.keys(EXTENSION_TO_TYPE).join(', ')}.`,
      'extension-not-allowed'
    );
  }
  return ext;
}

/**
 * Runs the full validation pipeline on a multer memory-storage file object.
 * Returns { type, ext, mime } of the verified file.
 */
function validateFile(file, { maxFileSize, maxFilenameLength }) {
  if (!file || !Buffer.isBuffer(file.buffer)) {
    throw new ValidationError('No file was uploaded.', 'no-file');
  }

  // Check 1: file name (length, characters, traversal, double extension, allow-list)
  const ext = validateFilename(file.originalname, maxFilenameLength);
  const type = EXTENSION_TO_TYPE[ext];
  const def = ALLOWED_TYPES[type];

  // Check 2: size (multer also enforces the maximum while streaming)
  if (file.size === 0 || file.buffer.length === 0) {
    throw new ValidationError('The file is empty.', 'empty-file');
  }
  if (file.buffer.length > maxFileSize) {
    throw new ValidationError('The file is too large.', 'too-large');
  }

  // Check 3: client-declared MIME type must match the extension
  if (file.mimetype !== def.mime) {
    throw new ValidationError('File content type does not match its extension.', `mime-mismatch:${file.mimetype}`);
  }

  // Check 4: magic bytes - the real content must match the claimed type
  if (!def.header(file.buffer)) {
    throw new ValidationError('File content does not match its extension.', 'magic-bytes-mismatch');
  }

  // Check 5: structure - file must end correctly (detects appended payloads)
  if (!def.trailer(file.buffer)) {
    throw new ValidationError('File structure is invalid or has data appended.', 'bad-trailer');
  }

  // Check 6: scan the content for embedded scripts / active content
  const content = file.buffer.toString('latin1');
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.regex.test(content)) {
      throw new ValidationError('File contains potentially malicious content.', `malicious-content:${pattern.name}`);
    }
  }

  return { type, ext: def.extensions[0], mime: def.mime };
}

/**
 * Produces a display-safe version of the original name. It is only ever
 * shown to users (as text) - it is never used to build a filesystem path.
 */
function sanitizeDisplayName(name) {
  return String(name)
    .normalize('NFKC')
    .replace(/[^\w.\- ()]/g, '_')
    .slice(0, 100);
}

module.exports = {
  ALLOWED_TYPES,
  EXTENSION_TO_TYPE,
  ValidationError,
  validateFile,
  validateFilename,
  sanitizeDisplayName,
};
