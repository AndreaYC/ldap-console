import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, downloadCSV, rdnValue, claim } from './dom.js';
import { parseNames, pivotGroups, cellLabel, listHeader, listRows } from './pivot.js';
import { plural } from './format.js';

const storageKey = 'ldap-console.bulk.names';
const maxNames = 200; // directory.MaxBulkNames

function loadText() {
  try {
    return localStorage.getItem(storageKey) || '';
  } catch {
    return '';
  }
}

function saveText(text) {
  try {
    localStorage.setItem(storageKey, text);
  } catch { /* storage unavailable: the form still works */ }
}

function cellNode(cell) {
  if (!cell) return h('span', { class: 'cell-none', 'aria-label': 'not a member' }, '·');
  if (cell.primary) return h('span', { class: 'tag primary', title: 'AD primary group (primaryGroupID)' }, 'primary');
  if (cell.direct) return h('span', { class: 'tag direct', title: 'direct member' }, 'direct');
  return h('span', { class: 'tag', title: 'nested via ' + cell.via.map(rdnValue).join(' › ') }, 'nested');
}

// problems lists names that did not resolve to exactly one account.
// Picking a candidate swaps that name for its DN in the text and reruns.
function problems(results, pick) {
  const bad = results.filter((p) => p.status !== 'found');
  if (!bad.length) return null;
  return h('div', { class: 'bulk-problems' }, bad.map((p) => h('div', { class: 'step ' + (p.status === 'notFound' ? 'warn' : 'fail') },
    h('div', { class: 'step-head' }, h('b', { class: 'mono' }, p.query), h('span', { class: 'muted' },
      p.status === 'notFound' ? 'no account matches this login, e-mail, CN, display name or DN'
        : p.status === 'ambiguous' ? `${p.matches.length} accounts match; pick one` + (p.truncated ? ' (list cut short)' : '')
          : p.error)),
    p.status === 'ambiguous' ? h('ul', { class: 'step-items' }, p.matches.map((o) => h('li', null,
      kindBadge(o.kind), entryLink(o.dn, o.name), h('span', { class: 'muted mono' }, o.dn),
      h('button', { type: 'button', onclick: () => pick(p.query, o.dn) }, 'Use this')))) : null)));
}

function pivotTable(pivot, results) {
  const { people, rows } = pivot;
  const selected = new Set();
  const filter = h('input', { type: 'search', name: 'filter-bulk', placeholder: 'Filter groups…', 'aria-label': 'Filter groups' });
  const show = h('select', { name: 'bulk-show', 'aria-label': 'Which groups' },
    h('option', { value: 'all' }, 'All groups'),
    h('option', { value: 'shared' }, 'Shared by everyone'),
    h('option', { value: 'direct' }, 'With a direct member'));
  const count = h('span', { class: 'muted' });
  const buildBtn = h('button', { type: 'button', disabled: true, onclick: () => {
    const q = new URLSearchParams();
    for (const dn of selected) q.append('group', dn);
    location.hash = '#/filters?' + q.toString();
  } }, 'Build filters from selected');
  const tbody = h('tbody');

  const updateBuild = () => {
    buildBtn.disabled = !selected.size;
    buildBtn.textContent = selected.size ? `Build filters from ${plural(selected.size, 'group')}` : 'Build filters from selected';
  };

  const render = () => {
    const q = filter.value.trim().toLowerCase();
    const mode = show.value;
    const visible = rows.filter((r) => (mode !== 'shared' || r.count === people.length) && (mode !== 'direct' || r.direct > 0) &&
      (!q || r.group.name.toLowerCase().includes(q) || r.group.dn.toLowerCase().includes(q)));
    count.textContent = `${visible.length} of ${plural(rows.length, 'group')}`;
    tbody.replaceChildren(...visible.map((r) => {
      const box = h('input', { type: 'checkbox', 'aria-label': 'Select ' + r.group.name, checked: selected.has(r.group.dn),
        onchange: (ev) => { if (ev.target.checked) selected.add(r.group.dn); else selected.delete(r.group.dn); updateBuild(); } });
      return h('tr', { class: r.count === people.length ? 'shared' : null },
        h('td', null, box),
        h('td', { class: 'nowrap' }, h('span', { class: 'namecell' }, kindBadge(r.group.kind), entryLink(r.group.dn, r.group.name))),
        h('td', { class: 'num', title: `${r.count} of ${people.length} people, ${r.direct} directly` }, `${r.count}/${people.length}`),
        r.cells.map((c) => h('td', { class: 'cell' }, cellNode(c))));
    }));
    if (!visible.length) tbody.append(h('tr', null, h('td', { colspan: people.length + 3, class: 'empty' }, 'No groups match')));
  };
  filter.addEventListener('input', render);
  show.addEventListener('change', render);

  const exportBtn = h('button', { type: 'button', onclick: () => downloadCSV('people-groups.csv',
    ['group', 'groupType', 'members', 'dn', ...people.map((p) => p.matches[0].name)],
    rows.map((r) => [r.group.name, r.group.groupType, r.count, r.group.dn, ...r.cells.map(cellLabel)])) }, 'Export matrix');
  const exportLong = h('button', { type: 'button', onclick: () => downloadCSV('people-groups-list.csv',
    listHeader, listRows(results)) }, 'Export list');

  const head = h('tr', null, h('th', null, ''), h('th', null, 'Group'), h('th', { class: 'num' }, 'People'),
    people.map((p) => h('th', { class: 'person' }, entryLink(p.matches[0].dn, p.matches[0].name),
      p.matches[0].disabled ? h('div', null, h('span', { class: 'tag disabled' }, 'disabled')) : null,
      p.truncated ? h('div', { class: 'muted', title: 'a safety limit was hit; this person may be in more groups' }, 'incomplete') : null)));

  render();
  return h('div', null,
    h('div', { class: 'toolbar' }, filter, show, count, h('span', { class: 'spacer' }), buildBtn, exportBtn, exportLong),
    h('div', { class: 'table-scroll' }, h('table', { class: 'pivot', 'aria-label': 'Groups by person' }, h('thead', null, head), tbody)));
}

// renderBulk looks up the groups of many people at once and lines them up
// side by side, so shared and missing memberships stand out.
export function renderBulk(el) {
  const text = h('textarea', { name: 'bulk-names', rows: 8, class: 'mono', spellcheck: 'false', 'aria-label': 'Names',
    placeholder: 'alice\nbob@corp.local\nCORP\\carol\nCN=Dave,OU=Users,DC=corp,DC=local' });
  text.value = loadText();
  const counter = h('span', { class: 'muted' });
  const out = h('section', { 'aria-live': 'polite' });
  const updateCount = () => {
    const n = parseNames(text.value).length;
    counter.textContent = n > maxNames ? `${n} names; at most ${maxNames} at a time` : plural(n, 'name');
    counter.classList.toggle('error-text', n > maxNames);
  };
  text.addEventListener('input', updateCount);

  const run = async () => {
    const names = parseNames(text.value);
    saveText(text.value);
    const current = claim(out);
    if (!names.length) return out.replaceChildren(errorBox(new Error('Enter at least one name.')));
    out.replaceChildren(loading(`Looking up ${plural(names.length, 'name')}…`));
    try {
      const res = await api.bulkGroups(names);
      if (!current()) return;
      const pivot = pivotGroups(res.people);
      const by = (s) => res.people.filter((p) => p.status === s).length;
      const missing = res.people.length - by('found');
      out.replaceChildren(...nodes(
        h('div', { class: 'stats' },
          h('span', null, h('b', null, by('found')), ' found'),
          pivot.people.length < by('found') ? h('span', null, h('b', null, pivot.people.length), ' distinct accounts') : null,
          missing ? h('span', null, h('b', null, by('notFound')), ' not found') : null,
          by('ambiguous') ? h('span', null, h('b', null, by('ambiguous')), ' ambiguous') : null,
          by('error') ? h('span', null, h('b', null, by('error')), ' failed') : null,
          h('span', null, h('b', null, pivot.rows.length), ' groups'),
          h('span', null, h('b', null, pivot.rows.filter((r) => r.count === pivot.people.length).length), ' shared by everyone')),
        problems(res.people, pick),
        pivot.people.length ? pivotTable(pivot, res.people) : null));
    } catch (err) {
      if (current()) out.replaceChildren(errorBox(err));
    }
  };

  // pick replaces an ambiguous name with the chosen account's DN, rewriting
  // the list one name per line (a DN's commas need a line of its own).
  const pick = (query, dn) => {
    text.value = parseNames(text.value).map((n) => (n.toLowerCase() === query.toLowerCase() ? dn : n)).join('\n');
    updateCount();
    run();
  };

  const form = h('form', { class: 'bulk-form', onsubmit: (ev) => { ev.preventDefault(); run(); } },
    h('h1', null, 'People → groups'),
    h('p', { class: 'muted' }, 'Paste names to see every group each person is in (direct, nested and AD primary), side by side. ',
      'A name can be a login (sAMAccountName or uid), DOMAIN\\login, a user principal name or e-mail, the exact CN or display name, or a full DN.'),
    text,
    h('div', { class: 'toolbar' }, h('span', { class: 'muted hint' }, 'One per line, or separated by commas or semicolons.'),
      counter, h('span', { class: 'spacer' }), h('button', { type: 'submit', class: 'primary' }, 'Look up groups')));
  el.replaceChildren(h('div', { class: 'page' }, form, out));
  updateCount();
}
