// Applies the saved theme before the page renders to avoid a flash.
// Loaded as an external file because the CSP forbids inline scripts.
(function () {
  try {
    const saved = localStorage.getItem('theme');
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.setAttribute('data-theme', saved);
    }
  } catch {
    /* storage unavailable - fall back to the system preference */
  }
})();
