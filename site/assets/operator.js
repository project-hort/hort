(() => {
  const root = document.documentElement;
  const theme = document.getElementById('theme-toggle');
  const menu = document.getElementById('menu-toggle');
  const links = document.getElementById('primary-navigation');
  function updateTheme() { if (theme) { const light = root.dataset.theme === 'light'; theme.textContent = light ? 'Dark mode' : 'Light mode'; theme.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme'); } }
  updateTheme();
  theme?.addEventListener('click', () => { root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light'; try { localStorage.setItem('hort-theme', root.dataset.theme); } catch (e) {} updateTheme(); });
  function close() { links?.classList.remove('is-open'); menu?.setAttribute('aria-expanded', 'false'); menu?.setAttribute('aria-label', 'Open navigation'); }
  menu?.addEventListener('click', () => { const on = links.classList.toggle('is-open'); menu.setAttribute('aria-expanded', String(on)); menu.setAttribute('aria-label', on ? 'Close navigation' : 'Open navigation'); });
  links?.addEventListener('click', e => { if (e.target.closest('a')) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && links?.classList.contains('is-open')) { close(); menu?.focus(); } });
  window.matchMedia('(min-width: 701px)').addEventListener('change', close);
})();
