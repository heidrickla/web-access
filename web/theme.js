// Served as a file: the proxy's Content-Security-Policy allows `script-src 'self'` only. Loaded as a
// classic script in <head>, so the stored theme applies before the page paints. Dark is the default;
// the choice is kept per browser, and the page works the same when storage is unavailable.

(() => {
  const KEY = 'wa:theme';
  const root = document.documentElement;

  function stored() {
    try { return localStorage.getItem(KEY); } catch { return null; }
  }

  function apply(theme) {
    root.dataset.theme = theme;
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    const label = theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
    button.title = label;
    button.setAttribute('aria-label', label);
  }

  apply(stored() === 'light' ? 'light' : 'dark');

  document.addEventListener('DOMContentLoaded', () => {
    apply(root.dataset.theme);
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    button.addEventListener('click', () => {
      const theme = root.dataset.theme === 'light' ? 'dark' : 'light';
      apply(theme);
      try { localStorage.setItem(KEY, theme); } catch { /* not persisted */ }
    });
  });
})();
