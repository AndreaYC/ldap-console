import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, downloadCSV, rdnValue, term } from './dom.js';

const presets = [
  ['All users', '(&(objectCategory=person)(objectClass=user))'],
  ['Disabled users', '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'],
  ['Locked out', '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))'],
  ['Password never expires', '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'],
  ['Empty groups', '(&(objectClass=group)(!(member=*)))'],
  ['Computers', '(objectClass=computer)'],
  ['Admins (adminCount=1)', '(adminCount=1)'],
  ['OpenLDAP people', '(objectClass=inetOrgPerson)'],
];

function valueNode(v) {
  return h('div', { class: 'val' + (v.binary ? ' bin' : '') },
    v.dn ? entryLink(v.text, rdnValue(v.text)) : v.text, v.note ? h('span', { class: 'note' }, v.note) : null);
}

// columnsOf keeps the order the attributes were asked for, then adds any
// others the server returned (e.g. for an empty attribute list).
function columnsOf(entries, requested) {
  const lower = new Map();
  for (const n of requested) if (n && n !== '*' && n !== '+') lower.set(n.toLowerCase(), null);
  for (const e of entries) {
    for (const a of e.attributes) {
      const k = a.name.toLowerCase();
      if (!lower.get(k)) lower.set(k, a.name);
    }
  }
  return [...lower.entries()].filter(([, name]) => name).map(([k, name]) => ({ key: k, name }));
}

function resultsTable(entries, requested) {
  const cols = columnsOf(entries, requested);
  const rows = entries.map((e) => {
    const byName = new Map(e.attributes.map((a) => [a.name.toLowerCase(), a]));
    return h('tr', null,
      h('td', { class: 'nowrap' }, h('span', { class: 'namecell' }, kindBadge(e.kind, e.dn), entryLink(e.dn, rdnValue(e.dn)))),
      cols.map((c) => h('td', null, (byName.get(c.key)?.values || []).map(valueNode))));
  });
  return h('div', { class: 'table-scroll' }, h('table', { 'aria-label': 'Search results' },
    h('thead', null, h('tr', null, h('th', null, 'Entry'), cols.map((c) => h('th', { class: 'mono' }, c.name)))),
    h('tbody', null, rows)));
}

// renderSearch draws the raw LDAP search form; state lives in the URL hash.
export function renderSearch(el, params, info) {
  const base = h('input', { value: params.get('base') || info.baseDN, 'aria-label': 'Base DN', class: 'mono' });
  const filter = h('input', { value: params.get('filter') || '', placeholder: '(&(objectClass=user)(sAMAccountName=j*))', 'aria-label': 'Filter', class: 'mono' });
  const attrs = h('input', { value: params.get('attrs') || 'cn,sAMAccountName,mail,memberOf', placeholder: 'cn,mail (empty = every column)', 'aria-label': 'Attributes', class: 'mono' });
  const scope = h('select', { 'aria-label': 'Scope' },
    [['sub', 'Everything below'], ['one', 'One level down'], ['base', 'Only this entry']].map(([s, label]) =>
      h('option', { value: s, selected: (params.get('scope') || 'sub') === s }, `${label} (${s})`)));
  const limit = h('input', { type: 'number', min: 1, max: 10000, value: params.get('limit') || '500', id: 'search-limit', class: 'limit' });
  const out = h('div');

  const submit = (ev) => {
    ev?.preventDefault();
    const q = new URLSearchParams({ base: base.value, filter: filter.value, attrs: attrs.value, scope: scope.value, limit: limit.value });
    location.hash = '#/search?' + q.toString();
  };

  const form = h('form', { class: 'form', onsubmit: submit },
    h('label', null, 'Presets'), h('div', { class: 'presets' }, presets.map(([label, f]) =>
      h('button', { type: 'button', onclick: () => { filter.value = f; submit(); } }, label))),
    h('label', null, term('base')), base,
    h('label', null, term('filter')), filter,
    h('label', null, term('attributes')), attrs,
    h('label', null, term('scope')), h('div', { class: 'row' }, scope,
      h('label', { for: 'search-limit', class: 'muted' }, 'Max results'), limit,
      h('span', { class: 'spacer' }), h('button', { class: 'primary', type: 'submit' }, 'Search')));

  el.replaceChildren(h('div', { class: 'page' }, form, out));
  if (params.get('filter')) run(out, Object.fromEntries(params));
}

async function run(out, params) {
  out.replaceChildren(loading('Searching…'));
  try {
    const res = await api.search(params);
    const exportBtn = h('button', {
      onclick: () => {
        const names = [...new Set(res.entries.flatMap((e) => e.attributes.map((a) => a.name)))];
        downloadCSV('search.csv', ['dn', ...names], res.entries.map((e) => [e.dn, ...names.map((n) =>
          (e.attributes.find((a) => a.name === n)?.values || []).map((v) => v.text).join('; '))]));
      },
    }, 'Export CSV');
    out.replaceChildren(...nodes(
      h('div', { class: 'toolbar' }, h('b', null, `${res.entries.length} entries`),
        res.truncated ? h('span', { class: 'muted' }, '(limit reached — narrow the filter or raise the limit)') : null,
        h('span', { class: 'spacer' }), exportBtn),
      res.entries.length ? resultsTable(res.entries, (params.attrs || '').split(',').map((a) => a.trim()))
        : h('div', { class: 'empty' }, 'No entries match')));
  } catch (err) {
    out.replaceChildren(errorBox(err));
  }
}
