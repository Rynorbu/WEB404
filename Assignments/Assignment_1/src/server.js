const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const config = require('./config');
const { FileStore } = require('./storage');
const { securityHeaders, rateLimiter, sameOriginOnly } = require('./middleware/security');
const { validateFile, sanitizeDisplayName, ValidationError } = require('./validators/fileValidator');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function createSecurityLogger(logDir) {
  fs.mkdirSync(logDir, { recursive: true });
  const logFile = path.join(logDir, 'security.log');
  return (event) => {
    const line = JSON.stringify({ time: new Date().toISOString(), ...event });
    fs.appendFile(logFile, line + '\n', () => {});
  };
}

function createApp(options = {}) {
  const opts = { ...config, ...options };
  const store = new FileStore(opts.uploadDir);
  const logSecurity = createSecurityLogger(opts.logDir);

  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(express.static(opts.publicDir));

  // Memory storage: the file is held in RAM and only written to disk AFTER
  // it has passed validation, so a malicious file never touches the disk.
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: opts.maxFileSize,
      files: opts.maxFilesPerRequest,
      fields: 5,
      parts: 6,
    },
  });

  app.post(
    '/api/upload',
    sameOriginOnly,
    rateLimiter({ windowMs: opts.rateLimitWindowMs, max: opts.rateLimitMax }),
    upload.single('file'),
    async (req, res, next) => {
      try {
        const verified = validateFile(req.file, opts);
        const record = await store.save(req.file.buffer, {
          ext: verified.ext,
          mime: verified.mime,
          displayName: sanitizeDisplayName(req.file.originalname),
        });
        logSecurity({ event: 'upload-accepted', ip: req.ip, id: record.id, sha256: record.sha256 });
        res.status(201).json({
          message: 'File uploaded successfully.',
          file: { id: record.id, originalName: record.originalName, mime: record.mime, size: record.size },
        });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/files', (req, res) => {
    res.json({ files: store.list() });
  });

  app.get('/api/files/:id', async (req, res) => {
    const { id } = req.params;
    // Strict format check before any lookup - blocks traversal like "../../etc"
    if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid file id.' });

    const record = store.find(id);
    if (!record) return res.status(404).json({ error: 'File not found.' });

    // Force download (never render inline) with the verified content type
    res.setHeader('Content-Type', record.mime);
    res.setHeader('Content-Disposition', `attachment; filename="${record.originalName.replace(/"/g, '')}"`);
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Cache-Control', 'private, no-store');
    res.sendFile(store.resolveSafe(record.storedName));
  });

  // Centralised error handler: generic messages to the client, details to the log
  app.use((err, req, res, next) => {
    const name = req.file ? sanitizeDisplayName(req.file.originalname) : undefined;

    if (err instanceof ValidationError) {
      logSecurity({ event: 'upload-rejected', ip: req.ip, reason: err.reason, name });
      return res.status(400).json({ error: err.message });
    }
    if (err instanceof multer.MulterError) {
      logSecurity({ event: 'upload-rejected', ip: req.ip, reason: err.code });
      const messages = {
        LIMIT_FILE_SIZE: [413, `File is too large. Maximum size is ${opts.maxFileSize / 1024 / 1024} MB.`],
        LIMIT_FILE_COUNT: [400, 'Only one file can be uploaded at a time.'],
        LIMIT_UNEXPECTED_FILE: [400, 'Unexpected file field.'],
      };
      const [status, message] = messages[err.code] || [400, 'Invalid upload request.'];
      return res.status(status).json({ error: message });
    }
    // Malformed multipart body (e.g. null bytes in headers) raised by the parser
    if (err.storageErrors !== undefined) {
      logSecurity({ event: 'upload-rejected', ip: req.ip, reason: `malformed-multipart:${err.message}` });
      return res.status(400).json({ error: 'Malformed upload request.' });
    }

    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
  });

  return app;
}

if (require.main === module) {
  createApp().listen(config.port, () => {
    console.log(`Secure upload server running at http://localhost:${config.port}`);
  });
}

module.exports = { createApp };
