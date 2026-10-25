// Small, progressive-enhancement script. The app is fully usable without it.
(function () {
  // Light / dark theme toggle. The current theme is stored in localStorage and
  // applied early by theme.js; here we only handle the click that switches it.
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      const root = document.documentElement;
      const prefersDark =
        window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const current =
        root.getAttribute('data-theme') || (prefersDark ? 'dark' : 'light');
      const next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try {
        localStorage.setItem('theme', next);
      } catch {
        /* storage unavailable - the theme still applies for this page view */
      }
    });
  }
})();

// Assignment 5: injection preset buttons fill the host field (vulnerable mode).
(function () {
  const host = document.getElementById('host');
  if (!host) return;
  document.querySelectorAll('.payload-btn[data-fill]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      host.value = btn.getAttribute('data-fill');
      host.focus();
    });
  });
})();
