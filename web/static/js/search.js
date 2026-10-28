import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, downloadCSV, rdnValue } from './dom.js';

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

function resultCard(e) {
  const rows = e.attributes.map((a) => h('tr', null,
    h('td', { class: 'attr-name' }, a.name),
    h('td', null, a.values.map((v) => h('div', { class: 'val' + (v.binary ? ' bin' : '') },
      v.dn ? entryLink(v.text) : v.text, v.note ? h('span', { class: 'note' }, v.note) : null)))));
  return h('div', { class: 'result' },
    h('div', { class: 'title' }, kindBadge(e.kind), entryLink(e.dn, rdnValue(e.dn)), h('span', { class: 'mono muted' }, e.dn)),
    rows.length ? h('table', null, h('tbody', null, rows)) : null);
}

// renderSearch draws the raw LDAP search form; state lives in the URL hash.
export function renderSearch(el, params, info) {
  const base = h('input', { value: params.get('base') || info.baseDN, 'aria-label': 'Base DN', class: 'mono' });
  const filter = h('input', { value: params.get('filter') || '', placeholder: '(&(objectClass=user)(sAMAccountName=j*))', 'aria-label': 'Filter', class: 'mono' });
  const attrs = h('input', { value: params.get('attrs') || 'cn,sAMAccountName,mail,memberOf', placeholder: 'cn,mail (empty = all)', 'aria-label': 'Attributes', class: 'mono' });
  const scope = h('select', { 'aria-label': 'Scope' },
    ['sub', 'one', 'base'].map((s) => h('option', { value: s, selected: (params.get('scope') || 'sub') === s }, s)));
  const limit = h('input', { type: 'number', min: 1, max: 10000, value: params.get('limit') || '500', 'aria-label': 'Limit' });
  const out = h('div');

  const submit = (ev) => {
    ev?.preventDefault();
    const q = new URLSearchParams({ base: base.value, filter: filter.value, attrs: attrs.value, scope: scope.value, limit: limit.value });
    location.hash = '#/search?' + q.toString();
  };

  const form = h('form', { class: 'form', onsubmit: submit },
    h('label', null, 'Base DN'), base,
    h('label', null, 'Filter'), filter,
    h('label', null, 'Attributes'), attrs,
    h('label', null, 'Scope'), h('div', { class: 'row' }, scope, limit, h('button', { class: 'primary', type: 'submit' }, 'Search')),
    h('label', null, 'Presets'), h('div', { class: 'presets' }, presets.map(([label, f]) =>
      h('button', { type: 'button', onclick: () => { filter.value = f; submit(); } }, label))));

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
      res.entries.length ? res.entries.map(resultCard) : h('div', { class: 'empty' }, 'No entries match')));
  } catch (err) {
    out.replaceChildren(errorBox(err));
  }
}
