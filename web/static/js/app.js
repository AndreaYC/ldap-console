import { api } from './api.js';
import { h, nodes, errorBox } from './dom.js';
import { createDirectory, directoryParams } from './directory.js';
import { renderConnect } from './connect.js';
import { renderLoginTest } from './logintest.js';
import { renderBulk } from './bulk.js';
import { renderAppLogin } from './applogin.js';
import { hostOf } from './format.js';

const main = document.getElementById('main');
let info;
let dir; // the Directory page, kept across navigations so its tree and search stay
let dirShown = false;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [view, query = ''] = raw.split('?');
  return { view: view || 'dir', params: new URLSearchParams(query) };
}

// Browse, Groups and Search became the Directory page; their URLs still work.
const directoryViews = new Set(['dir', 'browse', 'groups', 'search']);

async function route() {
  const { view, params } = parseHash();
  const tab = view === 'test' ? 'app' : directoryViews.has(view) ? 'dir' : view;
  for (const a of document.querySelectorAll('.views a')) a.classList.toggle('active', a.dataset.view === tab);

  if (view === 'connect' || !info.connected) return renderConnect(main, info);
  if (view === 'test') return renderLoginTest(main, info, params);
  if (view === 'people') return renderBulk(main, info);
  if (view === 'filters') { // the filter builder became the App login wizard
    history.replaceState(null, '', '#/app' + (params.toString() ? '?' + params : ''));
    return route();
  }
  if (view === 'app') return renderAppLogin(main, params, info);

  dir ??= createDirectory(info);
  if (main.firstChild !== dir.el) main.replaceChildren(dir.el);
  // The nav link (#/dir with nothing else) returns to the last search.
  if (view === 'dir' && !params.toString() && dirShown) return dir.restoreUrl();
  dirShown = true;
  dir.show(view === 'dir' ? params : directoryParams(view, params, info));
}

// "/" jumps to the Directory search from anywhere outside a text field.
function setupSlash() {
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== '/' || ev.metaKey || ev.ctrlKey || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '')) return;
    ev.preventDefault();
    const focus = () => document.querySelector('.dir-q')?.focus();
    if (location.hash.startsWith('#/dir')) return focus();
    // route() runs first: it was registered before this listener.
    window.addEventListener('hashchange', focus, { once: true });
    location.hash = '#/dir';
  });
}

// renderConn shows the server as a small chip; the details (bind DN, base,
// Switch) open in a panel.
function renderConn(el) {
  const row = (label, value, mono) => h('div', { class: 'conn-row' },
    h('span', { class: 'muted' }, label), h('span', { class: mono ? 'mono' : null }, value));
  el.replaceChildren(
    h('summary', { title: info.url },
      h('span', { class: 'dot', 'aria-hidden': 'true' }), h('span', { class: 'conn-host' }, hostOf(info.url), h('span', { class: 'muted' }, ' \u00b7 ' + (info.isAD ? 'Active Directory' : info.vendor || 'LDAP'))), h('span', { class: 'caret-down', 'aria-hidden': 'true' }, '▾')),
    h('div', { class: 'conn-panel' }, ...nodes(
      row('Server', info.url, true),
      row('Signed in as', info.bindDN || 'anonymous', true),
      row('Searching in', info.baseDN, true),
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
    return route();
  }
  renderConn(document.getElementById('conn'));
  setupSlash();
  route();
}

start();
