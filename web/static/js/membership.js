import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, downloadCSV, rdnValue, claim, term, membershipTag, membershipLegend } from './dom.js';
import { plural } from './format.js';

function tags(m) {
  return [
    membershipTag(m, (m.via || []).map(rdnValue)),
    m.disabled ? h('span', { class: 'tag disabled', title: 'Disabled (ACCOUNTDISABLE)' }, 'disabled') : null,
  ];
}

function viaCell(via) {
  if (!via?.length) return h('span', { class: 'muted' }, '—');
  const parts = [];
  via.forEach((dn, i) => {
    if (i) parts.push(' › ');
    parts.push(entryLink(dn, rdnValue(dn)));
  });
  return h('span', { class: 'via' }, parts);
}

function stats(items) {
  const direct = items.filter((m) => m.direct).length;
  const primary = items.filter((m) => m.primary).length; // AD marks these direct too
  const byKind = {};
  for (const m of items) byKind[m.kind] = (byKind[m.kind] || 0) + 1;
  return h('div', { class: 'stats' },
    h('span', null, h('b', null, items.length), ' total'),
    h('span', null, h('b', null, direct - primary), ' direct'),
    h('span', null, h('b', null, items.length - direct), ' via sub-groups'),
    primary ? h('span', null, h('b', null, primary), primary === 1 ? ' default group' : ' default groups') : null,
    Object.entries(byKind).map(([k, n]) => h('span', null, h('b', null, n), ' ', plural(n, k).replace(/^\d+ /, ''))));
}

// membershipTable renders a filterable list of memberships with CSV export.
function membershipTable(res, { title, csvName, showGroupType }) {
  const wrap = h('div');
  const filter = h('input', { type: 'search', name: 'filter-list', placeholder: 'Filter…', 'aria-label': 'Filter list' });
  const scope = h('select', { name: 'membership-type', 'aria-label': 'Membership type' },
    h('option', { value: 'all' }, 'All'),
    h('option', { value: 'direct' }, 'Only direct (direct)'),
    h('option', { value: 'nested' }, 'Only through sub-groups (nested)'));
  const tbody = h('tbody');

  const render = () => {
    const q = filter.value.trim().toLowerCase();
    const s = scope.value;
    tbody.replaceChildren();
    const rows = res.items.filter((m) =>
      (s === 'all' || (s === 'direct') === m.direct) &&
      (!q || m.name.toLowerCase().includes(q) || m.dn.toLowerCase().includes(q)));
    for (const m of rows) {
      tbody.append(h('tr', null,
        h('td', null, h('span', { class: 'namecell' }, kindBadge(m.kind), entryLink(m.dn, m.name)),
          m.kind === 'unknown' && m.description ? h('div', { class: 'notice' }, m.description) : null),
        showGroupType ? h('td', { class: 'muted' }, m.groupType || '') : null,
        h('td', null, tags(m)),
        h('td', null, viaCell(m.via))));
    }
    if (!rows.length) tbody.append(h('tr', null, h('td', { colspan: 4, class: 'empty' }, 'Nothing matches')));
  };
  filter.addEventListener('input', render);
  scope.addEventListener('change', render);

  const exportBtn = h('button', {
    onclick: () => downloadCSV(csvName,
      ['name', 'kind', 'direct', 'primary', 'disabled', 'groupType', 'via', 'dn'],
      res.items.map((m) => [m.name, m.kind, m.direct, !!m.primary, !!m.disabled, m.groupType || '',
        (m.via || []).map(rdnValue).join(' > '), m.dn])),
  }, 'Export CSV');

  wrap.append(...nodes(
    h('div', { class: 'toolbar' }, stats(res.items), h('span', { class: 'spacer' }), filter, scope, exportBtn),
    membershipLegend(),
    res.truncated ? h('div', { class: 'notice' }, 'Result truncated at the safety limit.') : null,
    h('table', { 'aria-label': title },
      h('thead', null, h('tr', null,
        h('th', null, 'Name'), showGroupType ? h('th', null, term('groupType')) : null, h('th', null, 'Membership'), h('th', null, 'Through'))),
      tbody)));
  render();
  return wrap;
}

export async function renderMemberOf(el, dn) {
  const current = claim(el);
  el.replaceChildren(loading('Resolving group memberships…'));
  try {
    const res = await api.userGroups(dn);
    if (!current()) return;
    el.replaceChildren(
      h('p', { class: 'notice' }, 'Every group this account is in: directly, through sub-groups (the Through column shows the path), and its default group.'),
      membershipTable(res, { title: 'Member of', csvName: `${res.subject.name}-groups.csv`, showGroupType: true }));
  } catch (err) {
    if (current()) el.replaceChildren(errorBox(err));
  }
}

export async function renderMembers(el, dn) {
  const nested = h('input', { type: 'checkbox', id: 'nested', name: 'nested', checked: true });
  const body = h('div');
  const head = h('div', { class: 'toolbar' },
    h('label', { for: 'nested' }, nested, ' ', term('nested', 'Include people in sub-groups')));
  claim(el); // drop a still-loading Member of response
  el.replaceChildren(head, body);

  // Toggling nested while a load runs must not let the older answer win.
  const load = async () => {
    const current = claim(body);
    const isNested = nested.checked;
    body.replaceChildren(loading('Resolving members…'));
    try {
      const res = await api.groupMembers(dn, isNested);
      if (!current()) return;
      body.replaceChildren(membershipTable(res, {
        title: 'Members', csvName: `${res.subject.name}-members${isNested ? '-nested' : ''}.csv`, showGroupType: false,
      }));
    } catch (err) {
      if (current()) body.replaceChildren(errorBox(err));
    }
  };
  nested.addEventListener('change', load);
  await load();
}
