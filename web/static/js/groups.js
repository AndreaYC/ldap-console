import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, downloadCSV, splitDN } from './dom.js';
import { containerPath } from './format.js';

// container returns the parent DN, e.g. "OU=Groups,DC=corp,DC=local".
function container(dn) {
  return splitDN(dn).slice(1).join(',');
}

// memberCount shows "100+" when AD was asked for only the first 100 members.
function memberCount(g) {
  if (!g.members) return '';
  return g.members.count + (g.members.more ? '+' : '');
}

const countHint = 'Direct members; on AD, 100+ means more than 100. Members through the AD primary group (e.g. Domain Users) are not counted.';

// renderGroups lists every group with type and location, filterable.
export async function renderGroups(el) {
  const page = h('div', { class: 'page' });
  el.replaceChildren(page);
  page.append(loading('Loading groups…'));
  let res;
  try {
    res = await api.groups();
  } catch (err) {
    page.replaceChildren(errorBox(err));
    return;
  }

  const types = [...new Set(res.items.map((g) => g.groupType).filter(Boolean))].sort();
  const filter = h('input', { type: 'search', name: 'filter-groups', placeholder: 'Filter by name, description or OU…', 'aria-label': 'Filter groups', class: 'wide' });
  const typeSel = h('select', { name: 'group-type', 'aria-label': 'Group type' },
    h('option', { value: '' }, 'All types'), types.map((t) => h('option', { value: t }, t)));
  const count = h('span', { class: 'muted' });
  const tbody = h('tbody');

  const render = () => {
    const q = filter.value.trim().toLowerCase();
    const t = typeSel.value;
    const rows = res.items.filter((g) => (!t || g.groupType === t) &&
      (!q || g.name.toLowerCase().includes(q) || (g.description || '').toLowerCase().includes(q) || g.dn.toLowerCase().includes(q)));
    count.textContent = `${rows.length} of ${res.items.length} groups`;
    tbody.replaceChildren(...rows.map((g) => h('tr', null,
      h('td', null, h('span', { class: 'namecell' }, kindBadge(g.kind), entryLink(g.dn, g.name))),
      h('td', { class: 'num' + (g.members?.count ? '' : ' muted') }, memberCount(g)),
      h('td', { class: 'muted' }, g.groupType || ''),
      h('td', null, g.description || ''),
      h('td', { class: 'muted', title: container(g.dn) }, containerPath(g.dn) || '(domain root)'))));
  };
  filter.addEventListener('input', render);
  typeSel.addEventListener('change', render);

  const exportBtn = h('button', {
    onclick: () => downloadCSV('groups.csv', ['name', 'members', 'groupType', 'description', 'container', 'dn'],
      res.items.map((g) => [g.name, memberCount(g), g.groupType || '', g.description || '', container(g.dn), g.dn])),
  }, 'Export CSV');

  page.replaceChildren(...nodes(
    h('div', { class: 'toolbar' }, filter, typeSel, count, h('span', { class: 'spacer' }), exportBtn),
    res.truncated ? h('div', { class: 'notice' }, 'List truncated at the safety limit.') : null,
    h('div', { class: 'table-scroll' }, h('table', { 'aria-label': 'Groups' },
      h('thead', null, h('tr', null, h('th', null, 'Group'), h('th', { class: 'num', title: countHint }, 'Members'), h('th', null, 'Type'), h('th', null, 'Description'), h('th', null, 'Container'))),
      tbody))));
  render();
}
