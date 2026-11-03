import { api } from './api.js';
import { h, nodes, entryLink, errorBox, loading, downloadCSV, rdnValue, claim } from './dom.js';
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

// mark draws one cell: a filled dot when directly in the group, a ring
// through a sub-group, a square for the AD default group, a faint dot when
// not in it. The words are in its title and aria-label.
function mark(cell, person, group) {
  let cls = 'm-none';
  let say = `${person} is not in ${group}`;
  if (cell?.primary) [cls, say] = ['m-primary', `${group} is ${person}’s default group (primary group)`];
  else if (cell?.direct) [cls, say] = ['m-direct', `${person} is directly in ${group}`];
  else if (cell) [cls, say] = ['m-nested', `${person} is in ${group} through ${cell.via.map(rdnValue).join(' › ')}`];
  return h('span', { class: 'mark-cell ' + cls, title: say, role: 'img', 'aria-label': say });
}

function legend() {
  return h('div', { class: 'mark-legend muted' },
    h('span', null, h('span', { class: 'mark-cell m-direct', 'aria-hidden': 'true' }), 'Directly in the group'),
    h('span', null, h('span', { class: 'mark-cell m-nested', 'aria-hidden': 'true' }), 'Through a sub-group (hover for the path)'),
    h('span', null, h('span', { class: 'mark-cell m-primary', 'aria-hidden': 'true' }), 'Default group (AD primary group)'));
}

// issues sums up names that did not resolve: not-found ones in one line,
// ambiguous ones each with their candidates to pick from.
function issues(results, pick) {
  const missing = results.filter((p) => p.status === 'notFound').map((p) => p.query);
  const failed = results.filter((p) => p.status === 'error');
  const ambiguous = results.filter((p) => p.status === 'ambiguous');
  const found = results.length - missing.length - failed.length - ambiguous.length;
  if (!missing.length && !failed.length && !ambiguous.length) return null;
  return h('div', { class: 'bulk-issues' }, ...nodes(
    h('div', { class: 'callout warn' }, `${found} of ${plural(results.length, 'name')} matched. `,
      ...nodes(missing.length ? [h('b', null, missing.join(', ')), missing.length === 1 ? ' wasn’t found. ' : ' weren’t found. '] : null,
        failed.length ? `${failed.length} couldn’t be read: ${failed.map((p) => `${p.query} (${p.error})`).join('; ')}. ` : null)),
    ambiguous.map((p) => h('div', { class: 'pick' },
      h('div', null, h('b', null, p.query), ` matches ${p.matches.length} accounts${p.truncated ? ' or more' : ''}. Which one?`),
      h('ul', null, p.matches.map((o) => h('li', null,
        h('button', { type: 'button', onclick: () => pick(p.query, o.dn) }, o.name),
        h('span', { class: 'muted mono' }, o.dn))))))));
}

function matrix(pivot, results) {
  const { people, rows } = pivot;
  const selected = new Set();
  let view = 'all';
  let nested = true;
  const find = h('input', { type: 'search', placeholder: 'Filter groups', 'aria-label': 'Filter groups', class: 'small-search' });
  const tabs = h('div', { class: 'seg', role: 'tablist', 'aria-label': 'Which groups' });
  const subs = h('input', { type: 'checkbox', checked: true });
  const useBtn = h('a', { class: 'button soft', hidden: true });
  const tbody = h('tbody');
  const has = (cell) => (cell && (nested || cell.direct || cell.primary) ? cell : null);

  const drawTabs = () => tabs.replaceChildren(...[['all', 'All groups'], ['shared', 'Shared by everyone']].map(([id, label]) =>
    h('button', { type: 'button', role: 'tab', 'aria-selected': String(view === id), class: view === id ? 'on' : '',
      onclick: () => { view = id; drawTabs(); render(); } }, label)));

  const updateUse = () => {
    useBtn.hidden = !selected.size;
    const q = new URLSearchParams();
    for (const dn of selected) q.append('group', dn);
    useBtn.href = '#/app?' + q;
    useBtn.textContent = `Use ${selected.size === 1 ? rdnValue([...selected][0]) : plural(selected.size, 'group')} for an app login →`;
  };

  const render = () => {
    const needle = find.value.trim().toLowerCase();
    const shown = rows.map((r) => ({ ...r, cells: r.cells.map(has) }))
      .map((r) => ({ ...r, count: r.cells.filter(Boolean).length }))
      .filter((r) => r.count > 0 && (view === 'all' || r.count === people.length) &&
        (!needle || r.group.name.toLowerCase().includes(needle)))
      .sort((a, b) => b.count - a.count || a.group.name.localeCompare(b.group.name, undefined, { sensitivity: 'base' }));
    tbody.replaceChildren(...shown.map((r) => h('tr', null,
      h('td', { class: 'pick-cell' }, h('input', { type: 'checkbox', 'aria-label': 'Select ' + r.group.name, checked: selected.has(r.group.dn),
        onchange: (ev) => { if (ev.target.checked) selected.add(r.group.dn); else selected.delete(r.group.dn); updateUse(); } })),
      h('td', null, entryLink(r.group.dn, r.group.name), ' ',
        h('span', { class: r.count === people.length ? 'everyone' : 'muted small' }, r.count === people.length ? 'everyone' : `${r.count} of ${people.length}`)),
      r.cells.map((c, i) => h('td', { class: 'cell' }, mark(c, people[i].matches[0].name, r.group.name))))));
    if (!shown.length) tbody.append(h('tr', null, h('td', { colspan: people.length + 2, class: 'empty' }, view === 'shared' ? 'No group has all of them.' : 'No groups match.')));
  };
  find.addEventListener('input', render);
  subs.addEventListener('change', () => { nested = subs.checked; render(); });

  const exportMenu = h('details', { class: 'menu export' }, h('summary', { class: 'button' }, 'Export ▾'),
    h('div', { class: 'menu-pop right' },
      h('button', { type: 'button', onclick: () => { exportMenu.open = false; downloadCSV('people-groups.csv',
        ['group', 'groupType', 'members', 'dn', ...people.map((p) => p.matches[0].name)],
        rows.map((r) => [r.group.name, r.group.groupType, r.count, r.group.dn, ...r.cells.map(cellLabel)])); } },
      h('span', null, 'Table (CSV)'), h('span', { class: 'muted' }, 'One row per group, one column per person')),
      h('button', { type: 'button', onclick: () => { exportMenu.open = false; downloadCSV('people-groups-list.csv', listHeader, listRows(results)); } },
        h('span', null, 'List (CSV)'), h('span', { class: 'muted' }, 'One row per person and group'))));
  document.addEventListener('click', (ev) => { if (exportMenu.open && !exportMenu.contains(ev.target)) exportMenu.open = false; });

  drawTabs();
  render();
  return h('div', { class: 'bulk-results' },
    h('div', { class: 'bulk-bar' }, tabs, h('label', { class: 'check' }, subs, ' Count sub-groups'), find,
      h('span', { class: 'spacer' }), useBtn, exportMenu),
    h('div', { class: 'table-scroll' }, h('table', { class: 'pivot', 'aria-label': 'Groups by person' },
      h('thead', null, h('tr', null, h('th', { class: 'pick-cell' }, h('span', { class: 'sr-only' }, 'Select')), h('th', null, 'Group'),
        people.map((p) => h('th', { class: 'person' }, entryLink(p.matches[0].dn, p.matches[0].name),
          p.matches[0].disabled ? h('div', null, h('span', { class: 'status off' }, 'disabled')) : null,
          p.truncated ? h('div', { class: 'muted small', title: 'A safety limit was hit; this person may be in more groups' }, 'incomplete') : null)))),
      tbody)),
    legend());
}

// renderBulk looks up the groups of many people at once and lines them up
// side by side, so shared and missing memberships stand out.
export function renderBulk(el) {
  const text = h('textarea', { name: 'bulk-names', rows: 3, class: 'mono', spellcheck: 'false', 'aria-label': 'Names',
    placeholder: 'alice, bob@corp.local, CORP\\carol\nor one per line' });
  text.value = loadText();
  const counter = h('span', { class: 'muted small' });
  const out = h('section', { 'aria-live': 'polite' });
  const updateCount = () => {
    const n = parseNames(text.value).length;
    counter.textContent = n > maxNames ? `${n} names — at most ${maxNames} at a time` : n ? plural(n, 'name') : '';
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
      out.replaceChildren(...nodes(issues(res.people, pick), pivot.people.length ? matrix(pivot, res.people) : null));
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

  text.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) { ev.preventDefault(); run(); } });
  el.replaceChildren(h('div', { class: 'page narrow' },
    h('div', { class: 'page-head' }, h('h1', null, 'Which groups are these people in?'),
      h('p', { class: 'muted' }, 'Paste login names, emails or names — separated by commas or one per line.')),
    h('form', { class: 'bulk-input', onsubmit: (ev) => { ev.preventDefault(); run(); } },
      text, h('div', { class: 'bulk-go' }, h('button', { type: 'submit', class: 'primary' }, 'Look up'), counter)),
    out));
  updateCount();
}
