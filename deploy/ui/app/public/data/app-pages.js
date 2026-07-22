/* Единый реестр страниц приложения (источник правды для RBAC UI). */

const AppPages = (() => {
  let pages = null;

  async function load() {
    if (pages) return pages;
    const res = await fetch('/data/app-pages.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('Не удалось загрузить реестр страниц');
    pages = await res.json();
    return pages;
  }

  function titlesMap(list) {
    return Object.fromEntries(list.map((p) => [p.id, { title: p.title, section: p.section }]));
  }

  function validIds(list) {
    return new Set(list.map((p) => p.id));
  }

  return { load, titlesMap, validIds };
})();

Object.assign(window, { AppPages });
