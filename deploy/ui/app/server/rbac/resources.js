const fs = require('fs');
const path = require('path');

let cached = null;

function loadAppPages() {
  if (cached) return cached;
  const filePath = path.join(__dirname, '..', '..', 'public', 'data', 'app-pages.json');
  const raw = fs.readFileSync(filePath, 'utf8');
  cached = JSON.parse(raw);
  return cached;
}

function pageIds() {
  return loadAppPages().map((p) => p.id);
}

function titlesMap() {
  return Object.fromEntries(
    loadAppPages().map((p) => [p.id, { title: p.title, section: p.section }]),
  );
}

module.exports = {
  loadAppPages,
  pageIds,
  titlesMap,
};
