// Client-side checks are for user experience only - the server re-validates
// everything, because anything in the browser can be bypassed.
const ALLOWED_EXT = ['png', 'jpg', 'jpeg', 'gif', 'pdf'];
const MAX_SIZE = 5 * 1024 * 1024;

const form = document.getElementById('upload-form');
const input = document.getElementById('file-input');
const dropZone = document.getElementById('drop-zone');
const dropText = document.getElementById('drop-text');
const statusEl = document.getElementById('status');
const list = document.getElementById('file-list');

function showStatus(message, type) {
  statusEl.textContent = message; // textContent, never innerHTML -> no XSS
  statusEl.className = type;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function checkFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) return `".${ext}" files are not allowed.`;
  if (file.size > MAX_SIZE) return 'File is larger than 5 MB.';
  if (file.size === 0) return 'File is empty.';
  return null;
}

input.addEventListener('change', () => {
  dropText.textContent = input.files[0] ? input.files[0].name : 'Click to choose a file or drag it here';
});

['dragover', 'dragenter'].forEach((evt) =>
  dropZone.addEventListener(evt, (e) => { e.preventDefault(); dropZone.classList.add('active'); })
);
['dragleave', 'drop'].forEach((evt) =>
  dropZone.addEventListener(evt, () => dropZone.classList.remove('active'))
);
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  input.files = e.dataTransfer.files;
  input.dispatchEvent(new Event('change'));
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = input.files[0];
  if (!file) return showStatus('Please choose a file.', 'error');

  const problem = checkFile(file);
  if (problem) return showStatus(problem, 'error');

  const data = new FormData();
  data.append('file', file);
  showStatus('Uploading...', 'info');

  try {
    const res = await fetch('/api/upload', { method: 'POST', body: data });
    const body = await res.json();
    if (!res.ok) return showStatus(body.error || 'Upload failed.', 'error');
    showStatus(body.message, 'success');
    form.reset();
    dropText.textContent = 'Click to choose a file or drag it here';
    loadFiles();
  } catch {
    showStatus('Network error. Please try again.', 'error');
  }
});

async function loadFiles() {
  const res = await fetch('/api/files');
  const { files } = await res.json();
  list.replaceChildren();

  if (files.length === 0) {
    const row = list.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.textContent = 'No files uploaded yet.';
    return;
  }

  for (const f of files.slice().reverse()) {
    const row = list.insertRow();
    row.insertCell().textContent = f.originalName;
    row.insertCell().textContent = f.mime;
    row.insertCell().textContent = formatSize(f.size);
    row.insertCell().textContent = new Date(f.uploadedAt).toLocaleString();
    const link = document.createElement('a');
    link.href = `/api/files/${encodeURIComponent(f.id)}`;
    link.textContent = 'Download';
    row.insertCell().appendChild(link);
  }
}

loadFiles();
