const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

/**
 * Stores validated files on disk under random, server-generated names and
 * keeps their metadata in an index file.
 */
class FileStore {
  constructor(uploadDir) {
    this.dir = path.resolve(uploadDir);
    this.indexPath = path.join(this.dir, 'index.json');
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o750 });
    this.records = fs.existsSync(this.indexPath)
      ? JSON.parse(fs.readFileSync(this.indexPath, 'utf8'))
      : [];
  }

  async save(buffer, { ext, mime, displayName }) {
    // Random UUID name: the user cannot choose, guess or overwrite file names
    const id = crypto.randomUUID();
    const storedName = `${id}.${ext}`;
    const target = this.resolveSafe(storedName);

    // 'wx' = fail if the file already exists; 0o640 = not executable
    await fsp.writeFile(target, buffer, { flag: 'wx', mode: 0o640 });

    const record = {
      id,
      storedName,
      originalName: displayName,
      mime,
      size: buffer.length,
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      uploadedAt: new Date().toISOString(),
    };
    this.records.push(record);
    await this.persist();
    return record;
  }

  find(id) {
    return this.records.find((r) => r.id === id);
  }

  list() {
    return this.records.map(({ id, originalName, mime, size, uploadedAt }) => ({
      id, originalName, mime, size, uploadedAt,
    }));
  }

  /** Resolves a name inside the upload dir and refuses anything outside it. */
  resolveSafe(name) {
    const full = path.resolve(this.dir, name);
    if (path.dirname(full) !== this.dir) {
      throw new Error('Path traversal attempt blocked');
    }
    return full;
  }

  async persist() {
    const tmp = `${this.indexPath}.tmp`;
    await fsp.writeFile(tmp, JSON.stringify(this.records, null, 2));
    await fsp.rename(tmp, this.indexPath);
  }
}

module.exports = { FileStore };
