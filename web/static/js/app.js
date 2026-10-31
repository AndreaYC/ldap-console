import { api } from './api.js';
import { h, nodes, kindBadge, errorBox, debounce, claim } from './dom.js';
import { Tree } from './tree.js';
import { renderEntry } from './entry.js';
import { renderSearch } from './search.js';
import { renderGroups } from './groups.js';
import { renderConnect } from './connect.js';
import { renderLoginTest } from './logintest.js';
import { renderBulk } from './bulk.js';
import { renderBuilder } from './builder.js';
import { hostOf } from './format.js';

const main = document.getElementById('main');
let info;
let browse; // { el, tree, detail } — kept across navigations so the tree keeps its state

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [view, query = ''] = raw.split('?');
  return { view: view || 'browse', params: new URLSearchParams(query) };
}

function ensureBrowse() {
  if (!browse) {
    const roots = info.namingContexts?.length ? info.namingContexts : [info.baseDN];
    const tree = new Tree(roots.includes(info.baseDN) ? roots : [info.baseDN, ...roots],
      (dn) => { location.hash = '#/browse?dn=' + encodeURIComponent(dn); });
    const detail = h('section', { class: 'detail', 'aria-label': 'Entry' });
    const el = h('div', { class: 'browse' }, h('aside', { class: 'sidebar', 'aria-label': 'Directory tree' }, tree.el), detail);
    browse = { el, tree, detail };
    const root = tree.nodes.get(info.baseDN.toLowerCase());
    if (root) tree.expand(root);
  }
  return browse;
}

async function route() {
  const { view, params } = parseHash();
  for (const a of document.querySelectorAll('.views a')) a.classList.toggle('active', a.dataset.view === view);

  if (view === 'connect' || !info.connected) return renderConnect(main, info);
  if (view === 'groups') return renderGroups(main);
  if (view === 'test') return renderLoginTest(main, info, params);
  if (view === 'people') return renderBulk(main);
  if (view === 'filters') return renderBuilder(main, params, info);
  if (view === 'search') return renderSearch(main, params, info);

  const b = ensureBrowse();
  if (main.firstChild !== b.el) main.replaceChildren(b.el);
  const dn = params.get('dn') || info.baseDN;
  b.tree.reveal(dn);
  renderEntry(b.detail, dn, params.get('tab'));
}

function setupFind() {
  const input = document.getElementById('find');
  const box = document.getElementById('find-results');
  let rows = [];
  let sel = -1;

  // close also invalidates an in-flight query, so a late answer cannot reopen the box.
  const close = () => { claim(box); box.hidden = true; sel = -1; };
  const go = (dn) => { close(); input.blur(); location.hash = '#/browse?dn=' + encodeURIComponent(dn); };
  const highlight = () => rows.forEach((r, i) => r.classList.toggle('sel', i === sel));

  const run = debounce(async () => {
    const q = input.value.trim();
    if (q.length < 2) return close();
    const current = claim(box); // results for "ab" must not replace those for "abc"
    try {
      const res = await api.find(q);
      if (!current()) return;
      rows =res.items.map((o) => h('div', { class: 'row', onmousedown: () => go(o.dn), title: o.dn },
        kindBadge(o.kind, o.dn), h('span', null, o.name), h('span', { class: 'muted mono find-dn' }, o.dn.split(',').slice(1, 3).join(','))));
      box.replaceChildren(...(rows.length ? rows : [h('div', { class: 'row muted' }, 'No matches')]));
      sel = -1;
      box.hidden = false;
    } catch (err) {
      if (!current()) return;
      box.replaceChildren(errorBox(err));
      box.hidden = false;
    }
  }, 250);

  input.addEventListener('input', run);
  input.addEventListener('blur', () => setTimeout(close, 150));
  input.addEventListener('keydown', (ev) => {
    if (box.hidden || !rows.length) return;
    if (ev.key === 'ArrowDown') { sel = Math.min(sel + 1, rows.length - 1); highlight(); ev.preventDefault(); }
    if (ev.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); highlight(); ev.preventDefault(); }
    if (ev.key === 'Enter') go(rows[Math.max(sel, 0)].title);
    if (ev.key === 'Escape') close();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === '/' && document.activeElement?.tagName !== 'INPUT') { ev.preventDefault(); input.focus(); }
  });
}

// renderConn shows the server as a small chip; the details (bind DN, base,
// Switch) open in a panel so the header keeps room for the find box.
function renderConn(el) {
  const row = (label, value, mono) => h('div', { class: 'conn-row' },
    h('span', { class: 'muted' }, label), h('span', { class: mono ? 'mono' : null }, value));
  el.replaceChildren(
    h('summary', { title: info.url },
      h('span', { class: 'dot', 'aria-hidden': 'true' }), h('span', { class: 'conn-host' }, hostOf(info.url)), h('span', { class: 'caret-down', 'aria-hidden': 'true' }, '▾')),
    h('div', { class: 'conn-panel' }, ...nodes(
      row('Server', info.url, true),
      row('Bound as', info.bindDN || 'anonymous', true),
      row('Base DN', info.baseDN, true),
      h('div', { class: 'conn-row' }, h('span', { class: 'pill' }, info.vendor || 'LDAP'),
        info.readOnly ? h('span', { class: 'pill ro' }, 'read-only') : null),
      h('div', { class: 'conn-actions' }, h('a', { href: '#/connect', class: 'button', onclick: () => { el.open = false; } }, 'Switch server…')))));
  el.hidden = false;
  document.addEventListener('click', (ev) => { if (el.open && !el.contains(ev.target)) el.open = false; });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') el.open = false; });
  window.addEventListener('hashchange', () => { el.open = false; });
}

async function start() {
  try {
    info = await api.info();
  } catch (err) {
    main.replaceChildren(h('div', { class: 'page' }, errorBox(err)));
    return;
  }
  window.addEventListener('hashchange', route);
  if (!info.connected) {
    document.querySelector('.views').hidden = true;
    document.querySelector('.find').hidden = true;
    return route();
  }
  renderConn(document.getElementById('conn'));
  setupFind();
  route();
}

start();
