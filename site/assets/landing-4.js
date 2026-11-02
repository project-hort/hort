
(() => {
  const button = document.getElementById('menu-toggle');
  const links = document.getElementById('primary-navigation');
  if (!button || !links) return;
  function close() {
    links.classList.remove('is-open');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-label', 'Open navigation');
  }
  button.addEventListener('click', () => {
    const opened = links.classList.toggle('is-open');
    button.setAttribute('aria-expanded', String(opened));
    button.setAttribute('aria-label', opened ? 'Close navigation' : 'Open navigation');
  });
  links.addEventListener('click', event => {
    if (event.target.closest('a')) close();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') { close(); button.focus(); }
  });
  window.matchMedia('(min-width: 701px)').addEventListener('change', close);
})();
