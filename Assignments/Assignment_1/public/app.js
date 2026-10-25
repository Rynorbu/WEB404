// Client-side checks are for user experience only - the server re-validates
// everything, because anything in the browser can be bypassed.
// All user-controlled text is inserted with textContent (never innerHTML).

const ALLOWED_EXT = ['png', 'jpg', 'jpeg', 'gif', 'pdf'];
const MAX_SIZE = 5 * 1024 * 1024;
const SERVER_CHECKS = [
  'File name is safe',
  'Extension allowed',
  'Type matches content',
  'File signature valid',
  'Structure intact',
  'No hidden code found',
];

const $ = (id) => document.getElementById(id);
const form = $('upload-form');
const input = $('file-input');
const dropzone = $('dropzone');
const selected = $('selected');
const selectedThumb = $('selected-thumb');
const selectedName = $('selected-name');
const selectedMeta = $('selected-meta');
const progress = $('progress');
const progressBar = $('progress-bar');
const clearBtn = $('clear-btn');
const result = $('result');
const uploadBtn = $('upload-btn');
const uploadBtnText = $('upload-btn-text');
const list = $('file-list');
const empty = $('empty');
const summary = $('files-summary');
const search = $('search');

let currentFile = null;
let previewUrl = null;
let allFiles = [];
let highlightId = null;
let uploading = false;

/* ------------------------------------------------------------------ helpers */

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.appendChild(use);
  return svg;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function timeAgo(iso) {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 45) return 'just now';
  const units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60]];
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of units) {
    if (seconds >= size) return rtf.format(-Math.floor(seconds / size), unit);
  }
  return 'just now';
}

function extOf(name) {
  const parts = name.split('.');
  return parts.length > 1 ? parts.pop().toLowerCase() : '';
}

function kindOf(mimeOrExt) {
  if (/pdf/.test(mimeOrExt)) return 'pdf';
  if (/image|png|jpe?g|gif/.test(mimeOrExt)) return 'image';
  return 'other';
}

function typeBadge(kind) {
  const wrap = el('span', `type-icon type-${kind}`);
  wrap.appendChild(icon(kind === 'pdf' ? 'pdf' : kind === 'image' ? 'image' : 'file'));
  return wrap;
}

function labelFor(mime) {
  return { 'image/png': 'PNG', 'image/jpeg': 'JPG', 'image/gif': 'GIF', 'application/pdf': 'PDF' }[mime] || 'FILE';
}

/* ------------------------------------------------------------------ toasts */

function toast(message, type = 'info') {
  const t = el('div', `toast ${type}`);
  t.setAttribute('role', type === 'error' ? 'alert' : 'status');
  t.appendChild(icon(type === 'success' ? 'check' : type === 'error' ? 'alert' : 'shield'));
  t.appendChild(el('div', 'toast-body', message));
  const close = el('button', 'icon-btn toast-close');
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss notification');
  close.appendChild(icon('x'));
  t.appendChild(close);

  const dismiss = () => {
    t.classList.add('leaving');
    t.addEventListener('animationend', () => t.remove(), { once: true });
  };
  close.addEventListener('click', dismiss);
  setTimeout(dismiss, 5000);
  $('toasts').appendChild(t);
}

/* ------------------------------------------------------------------ theme */

$('theme-toggle').addEventListener('click', () => {
  const root = document.documentElement;
  const current = root.getAttribute('data-theme') ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('theme', next); } catch { /* not persisted */ }
});

/* ------------------------------------------------------------------ selection */

function validateLocally(file) {
  const ext = extOf(file.name);
  if (!ALLOWED_EXT.includes(ext)) {
    return ext ? `".${ext}" files aren't allowed. Choose a PNG, JPG, GIF or PDF.` : 'This file has no extension.';
  }
  if (file.size === 0) return 'This file is empty.';
  if (file.size > MAX_SIZE) return `This file is ${formatSize(file.size)}. The maximum is 5 MB.`;
  return null;
}

function hideResult() {
  result.hidden = true;
  result.replaceChildren();
}

function showResult(type, title, detail, checks) {
  result.className = `result ${type}`;
  result.replaceChildren();
  result.appendChild(icon(type === 'success' ? 'check' : 'alert'));
  const body = el('div');
  body.appendChild(el('div', 'result-title', title));
  if (detail) body.appendChild(el('p', '', detail));
  if (checks) {
    const ul = el('ul', 'checks');
    checks.forEach((c, i) => {
      const li = el('li');
      li.style.animationDelay = `${i * 70}ms`;
      li.appendChild(icon('check'));
      li.appendChild(document.createTextNode(c));
      ul.appendChild(li);
    });
    body.appendChild(ul);
  }
  result.appendChild(body);
  result.hidden = false;
}

function selectFile(file) {
  if (uploading) return;
  hideResult();
  const problem = validateLocally(file);
  if (problem) {
    clearSelection();
    showResult('error', "This file can't be uploaded", problem);
    return;
  }

  currentFile = file;
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;

  selectedThumb.replaceChildren();
  const kind = kindOf(file.type || extOf(file.name));
  if (kind === 'image') {
    previewUrl = URL.createObjectURL(file);
    const img = el('img');
    img.alt = '';
    img.src = previewUrl;
    img.addEventListener('error', () => selectedThumb.replaceChildren(typeBadge(kind)), { once: true });
    selectedThumb.appendChild(img);
  } else {
    selectedThumb.appendChild(typeBadge(kind));
  }

  selectedName.textContent = file.name;
  selectedMeta.textContent = `${formatSize(file.size)} · Ready to upload`;
  progress.hidden = true;
  progressBar.style.width = '0%';
  selected.hidden = false;
  dropzone.hidden = true;
  uploadBtn.disabled = false;
  uploadBtn.focus();
}

function clearSelection() {
  currentFile = null;
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  input.value = '';
  selected.hidden = true;
  dropzone.hidden = false;
  uploadBtn.disabled = true;
}

input.addEventListener('change', () => {
  if (input.files[0]) selectFile(input.files[0]);
});

dropzone.addEventListener('click', () => input.click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    input.click();
  }
});

let dragDepth = 0;
dropzone.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
dropzone.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; dropzone.classList.remove('dragover'); } });
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  dropzone.classList.remove('dragover');
  const files = e.dataTransfer.files;
  if (files.length > 1) toast('Only one file can be uploaded at a time. Using the first one.', 'info');
  if (files[0]) selectFile(files[0]);
});

// Stop the browser from opening files dropped outside the drop zone
['dragover', 'drop'].forEach((evt) => window.addEventListener(evt, (e) => e.preventDefault()));

clearBtn.addEventListener('click', () => {
  if (uploading) return;
  clearSelection();
  hideResult();
  dropzone.focus();
});

/* ------------------------------------------------------------------ upload */

function setUploading(state) {
  uploading = state;
  uploadBtn.disabled = state || !currentFile;
  uploadBtn.classList.toggle('loading', state);
  uploadBtnText.textContent = state ? 'Uploading & scanning…' : 'Upload securely';
  clearBtn.disabled = state;
}

function sendFile(file, onProgress) {
  // XMLHttpRequest (not fetch) so we can report upload progress
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.responseType = 'json';
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total);
    });
    xhr.addEventListener('load', () => resolve({ status: xhr.status, body: xhr.response || {} }));
    xhr.addEventListener('error', () => reject(new Error('network')));
    const data = new FormData();
    data.append('file', file);
    xhr.send(data);
  });
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!currentFile || uploading) return;

  hideResult();
  setUploading(true);
  progress.hidden = false;
  progressBar.style.width = '0%';
  selectedMeta.textContent = `${formatSize(currentFile.size)} · Uploading…`;

  try {
    const { status, body } = await sendFile(currentFile, (ratio) => {
      progressBar.style.width = `${Math.round(ratio * 100)}%`;
      if (ratio >= 1) selectedMeta.textContent = `${formatSize(currentFile.size)} · Running security checks…`;
    });

    if (status === 201) {
      highlightId = body.file.id;
      showResult('success', 'Upload complete: file passed all security checks', null, SERVER_CHECKS);
      toast(`"${body.file.originalName}" uploaded successfully.`, 'success');
      clearSelection();
      await loadFiles();
    } else {
      const hint = status === 429
        ? 'You have uploaded too many files. Please wait a few minutes and try again.'
        : status === 413
          ? 'Please choose a file smaller than 5 MB.'
          : 'Only genuine PNG, JPG, GIF or PDF files are accepted.';
      showResult('error', body.error || 'Upload blocked', hint);
      selectedMeta.textContent = `${formatSize(currentFile.size)} · Blocked`;
      progress.hidden = true;
      toast('Upload blocked by security checks.', 'error');
    }
  } catch {
    showResult('error', 'Network error', 'Check your connection and try again.');
    progress.hidden = true;
    selectedMeta.textContent = `${formatSize(currentFile.size)} · Not uploaded`;
  } finally {
    setUploading(false);
  }
});

/* ------------------------------------------------------------------ file list */

function renderSkeleton() {
  list.replaceChildren();
  empty.hidden = true;
  for (let i = 0; i < 3; i++) {
    const li = el('li', 'file-item skeleton');
    li.appendChild(el('div', 'file-thumb'));
    const main = el('div', 'file-main');
    main.appendChild(el('div', 'sk-line'));
    main.appendChild(el('div', 'sk-line'));
    li.appendChild(main);
    list.appendChild(li);
  }
}

function renderFiles() {
  const q = search.value.trim().toLowerCase();
  const files = allFiles
    .slice()
    .reverse()
    .filter((f) => !q || f.originalName.toLowerCase().includes(q));

  const total = allFiles.reduce((sum, f) => sum + f.size, 0);
  summary.textContent = allFiles.length
    ? `${allFiles.length} file${allFiles.length === 1 ? '' : 's'} · ${formatSize(total)} total`
    : 'Nothing uploaded yet';

  list.replaceChildren();
  if (files.length === 0) {
    $('empty-title').textContent = q ? 'No matching files' : 'No files yet';
    $('empty-text').textContent = q ? `Nothing matches "${search.value.trim()}".` : 'Files you upload will appear here.';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  files.forEach((f, i) => {
    const li = el('li', 'file-item');
    li.style.animationDelay = `${Math.min(i, 10) * 30}ms`;
    if (f.id === highlightId) li.classList.add('new');

    const thumb = el('div', 'file-thumb');
    thumb.appendChild(typeBadge(kindOf(f.mime)));
    li.appendChild(thumb);

    const main = el('div', 'file-main');
    const name = el('p', 'file-name', f.originalName);
    name.title = f.originalName;
    main.appendChild(name);

    const meta = el('div', 'file-meta');
    meta.appendChild(el('span', 'badge', labelFor(f.mime)));
    meta.appendChild(el('span', '', formatSize(f.size)));
    meta.appendChild(el('span', 'sep'));
    const time = el('time', '', timeAgo(f.uploadedAt));
    time.dateTime = f.uploadedAt;
    time.title = new Date(f.uploadedAt).toLocaleString();
    meta.appendChild(time);
    meta.appendChild(el('span', 'sep v'));
    const verified = el('span', 'verified');
    verified.appendChild(icon('check'));
    verified.appendChild(document.createTextNode('Verified'));
    meta.appendChild(verified);
    main.appendChild(meta);
    li.appendChild(main);

    const dl = el('a', 'download-btn');
    dl.href = `/api/files/${encodeURIComponent(f.id)}`;
    dl.setAttribute('aria-label', `Download ${f.originalName}`);
    dl.appendChild(icon('download'));
    dl.appendChild(el('span', '', 'Download'));
    li.appendChild(dl);

    list.appendChild(li);
  });
}

async function loadFiles({ showSkeleton = false } = {}) {
  if (showSkeleton) renderSkeleton();
  try {
    const res = await fetch('/api/files');
    if (!res.ok) throw new Error();
    allFiles = (await res.json()).files;
    renderFiles();
  } catch {
    list.replaceChildren();
    summary.textContent = 'Could not load files';
    toast('Could not load your files. Please refresh.', 'error');
  }
}

search.addEventListener('input', renderFiles);
$('refresh-btn').addEventListener('click', () => loadFiles({ showSkeleton: true }));

loadFiles({ showSkeleton: true });
