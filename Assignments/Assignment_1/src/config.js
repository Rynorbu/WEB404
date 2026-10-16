const path = require('path');

const ROOT = path.resolve(__dirname, '..');

module.exports = {
  port: Number(process.env.PORT) || 3000,

  // Uploaded files live OUTSIDE the public web root so they can never be
  // requested directly or executed by the web server.
  uploadDir: process.env.UPLOAD_DIR || path.join(ROOT, 'uploads'),
  logDir: process.env.LOG_DIR || path.join(ROOT, 'logs'),
  publicDir: path.join(ROOT, 'public'),

  maxFileSize: 5 * 1024 * 1024, // 5 MB
  maxFilesPerRequest: 1,
  maxFilenameLength: 255,

  // Rate limiting: uploads per IP per window
  rateLimitWindowMs: 15 * 60 * 1000,
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || 20,
};
