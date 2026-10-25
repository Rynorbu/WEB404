// Applies the saved colour theme before the page renders, to avoid a flash of
// the wrong theme. Loaded as an external file (no inline script).
(function () {
  try {
    const saved = localStorage.getItem('theme');
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.setAttribute('data-theme', saved);
    }
  } catch {
    /* storage unavailable - fall back to the system preference via CSS */
  }
})();
