import { api } from './api.js';
import { h, kindBadge, entryLink, errorBox, loading, copyButton, rdnValue } from './dom.js';
import { renderMemberOf, renderMembers } from './membership.js';

function valueNode(v) {
  if (v.dn) return h('div', { class: 'val' }, entryLink(v.text));
  return h('div', { class: 'val' + (v.binary ? ' bin' : '') },
    v.text, v.note ? h('span', { class: 'note' }, v.note) : null);
}

function attributesTable(entry) {
  const filter = h('input', { type: 'search', name: 'filter-attrs', placeholder: 'Filter attributes…', 'aria-label': 'Filter attributes' });
  const tbody = h('tbody');
  const render = () => {
    const q = filter.value.trim().toLowerCase();
    tbody.replaceChildren();
    for (const a of entry.attributes) {
      if (q && !a.name.toLowerCase().includes(q) && !a.values.some((v) => v.text.toLowerCase().includes(q))) continue;
      tbody.append(h('tr', null,
        h('td', { class: 'attr-name' }, a.name, a.values.length > 1 ? h('div', { class: 'muted' }, `${a.values.length} values`) : null),
        h('td', null, a.values.map(valueNode))));
    }
  };
  filter.addEventListener('input', render);
  render();
  return h('div', null,
    h('div', { class: 'toolbar' }, h('span', { class: 'muted' }, `${entry.attributes.length} attributes`), h('span', { class: 'spacer' }), filter),
    h('table', { 'aria-label': 'Attributes' }, h('thead', null, h('tr', null, h('th', null, 'Attribute'), h('th', null, 'Values'))), tbody));
}

const membershipKinds = new Set(['user', 'computer', 'group', 'foreignSecurityPrincipal', 'contact']);

// renderEntry shows one entry with Attributes / Member of / Members tabs.
export async function renderEntry(el, dn, tab) {
  el.replaceChildren(loading());
  let entry;
  try {
    entry = await api.entry(dn);
  } catch (err) {
    el.replaceChildren(errorBox(err));
    return;
  }
  const name = entry.attributes.find((a) => /^(displayName|cn|ou)$/i.test(a.name))?.values[0]?.text || rdnValue(dn);

  const tabs = [['attributes', 'Attributes']];
  if (membershipKinds.has(entry.kind)) tabs.push(['memberof', 'Member of']);
  if (entry.kind === 'group') tabs.push(['members', 'Members']);
  // Membership is what people open an account or a group for; Attributes stays one click away.
  if (!tabs.some(([id]) => id === tab)) tab = entry.kind === 'group' ? 'members' : membershipKinds.has(entry.kind) ? 'memberof' : 'attributes';

  const body = h('div');
  const bar = h('div', { class: 'tabs', role: 'tablist' });
  const show = (id) => {
    for (const b of bar.children) b.classList.toggle('active', b.dataset.tab === id);
    history.replaceState(null, '', `#/browse?dn=${encodeURIComponent(dn)}&tab=${id}`);
    if (id === 'attributes') body.replaceChildren(attributesTable(entry));
    if (id === 'memberof') renderMemberOf(body, dn);
    if (id === 'members') renderMembers(body, dn);
  };
  for (const [id, label] of tabs) {
    const b = h('button', { role: 'tab', onclick: () => show(id) }, label);
    b.dataset.tab = id;
    bar.append(b);
  }

  el.replaceChildren(
    h('div', { class: 'head' }, kindBadge(entry.kind, entry.dn), h('h1', null, name)),
    h('div', { class: 'dnline' }, h('span', { class: 'mono' }, entry.dn), copyButton(entry.dn)),
    bar, body);
  show(tab);
}
