import { api } from './api.js';
import { h, nodes, kindBadge, errorBox, debounce } from './dom.js';
import { Tree } from './tree.js';
import { renderEntry } from './entry.js';
import { renderSearch } from './search.js';
import { renderGroups } from './groups.js';

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

  if (view === 'groups') return renderGroups(main);
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

  const close = () => { box.hidden = true; sel = -1; };
  const go = (dn) => { close(); input.blur(); location.hash = '#/browse?dn=' + encodeURIComponent(dn); };
  const highlight = () => rows.forEach((r, i) => r.classList.toggle('sel', i === sel));

  const run = debounce(async () => {
    const q = input.value.trim();
    if (q.length < 2) return close();
    try {
      const res = await api.find(q);
      rows = res.items.map((o) => h('div', { class: 'row', onmousedown: () => go(o.dn), title: o.dn },
        kindBadge(o.kind), h('span', null, o.name), h('span', { class: 'muted mono find-dn' }, o.dn.split(',').slice(1, 3).join(','))));
      box.replaceChildren(...(rows.length ? rows : [h('div', { class: 'row muted' }, 'No matches')]));
      sel = -1;
      box.hidden = false;
    } catch (err) {
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

async function start() {
  try {
    info = await api.info();
  } catch (err) {
    main.replaceChildren(h('div', { class: 'page' }, errorBox(err)));
    return;
  }
  document.getElementById('conn').replaceChildren(...nodes(
    h('span', { class: 'pill' }, info.vendor || 'LDAP'),
    h('span', { class: 'mono', title: 'Server' }, info.url),
    h('span', { title: 'Bound as' }, '· ', info.bindDN || 'anonymous'),
    info.readOnly ? h('span', { class: 'pill ro' }, 'read-only') : null));
  setupFind();
  window.addEventListener('hashchange', route);
  route();
}

start();
