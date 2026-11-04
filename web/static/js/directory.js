import { api } from './api.js';
import { h, nodes, kindBadge, errorBox, loading, claim, debounce, downloadCSV, rdnValue, splitDN } from './dom.js';
import { Tree } from './tree.js';
import { renderEntry } from './entry.js';
import { runExplain } from './explain.js';
import { allGroups } from './grouppicker.js';
import { toFilter, fromFilter, chipWords, kinds, types, presets, fieldOpLabels } from './conditions.js';
import { containerPath, ouPath, plural } from './format.js';
import { isGlobalCatalog, presetBlind, gcBlindKind, gcNote, gcSearchWarning, gcGroupsWarning } from './catalog.js';

const limit = 1000;
const kindWords = { container: 'Folder', user: 'Person', group: 'Group', computer: 'Computer', contact: 'Contact', foreignSecurityPrincipal: 'Other domain', other: 'Other', unknown: 'Unknown' };
const kindWord = (e) => kindWords[e.kind] || e.kind;
const commonFields = ['department', 'title', 'company', 'mail', 'l', 'manager', 'description', 'telephoneNumber', 'employeeID', 'physicalDeliveryOfficeName'];

// What each type of result shows, besides its name and folder.
function columnsFor(type, isAD) {
  if (type === 'people') {
    return {
      attrs: ['cn', 'displayName', isAD ? 'sAMAccountName' : 'uid', 'mail', ...(isAD ? ['userAccountControl'] : [])],
      cols: [['Login', (e) => text(e, isAD ? 'sAMAccountName' : 'uid'), 'mono'], ['Email', (e) => text(e, 'mail')], ...(isAD ? [['Status', status]] : [])],
    };
  }
  if (type === 'groups') {
    return {
      attrs: ['cn', 'description', ...(isAD ? ['groupType', 'member;range=0-99'] : ['member', 'uniqueMember', 'memberUid'])],
      cols: [['Members', memberCount, 'num'], ...(isAD ? [['Type', (e) => vals(e, 'groupType')[0]?.note || '']] : []), ['Description', (e) => text(e, 'description')]],
    };
  }
  if (type === 'computers') {
    return { attrs: ['cn', 'operatingSystem', 'userAccountControl'], cols: [['System', (e) => text(e, 'operatingSystem')], ['Status', status]] };
  }
  return { attrs: ['cn', 'displayName', 'ou', 'description', 'userAccountControl'], cols: [['Kind', kindWord], ['Description', (e) => text(e, 'description')]] };
}

function vals(e, name) {
  const lower = name.toLowerCase();
  return e.attributes?.find((a) => a.name.toLowerCase() === lower || a.name.toLowerCase().startsWith(lower + ';'))?.values || [];
}
function text(e, name) {
  return vals(e, name).map((v) => v.text).join(', ');
}
function isDisabled(e) {
  return e.disabled ?? /ACCOUNTDISABLE/.test(vals(e, 'userAccountControl')[0]?.note || '');
}
function status(e) {
  const off = isDisabled(e);
  return h('span', { class: 'status ' + (off ? 'off' : 'on') }, off ? 'Disabled' : 'Active');
}
function memberCount(e) {
  const a = e.attributes?.find((x) => /^(member|uniqueMember|memberUid)(;|$)/i.test(x.name));
  if (!a) return '0';
  const more = /;range=\d+-\d+$/i.test(a.name);
  return a.values.length + (more ? '+' : '');
}
function displayName(e) {
  return e.name || text(e, 'displayName') || text(e, 'cn') || rdnValue(e.dn);
}
function cellText(v) {
  return v instanceof Node ? v.textContent : String(v ?? '');
}

// createDirectory builds the Directory page once; show() applies a URL.
// It merges what were the Browse, Groups and Search pages: a folder tree
// and saved views, a search box with filter chips, the results, and the
// selected entry's details.
export function createDirectory(info) {
  const roots = info.namingContexts?.length ? info.namingContexts : [info.baseDN];
  const st = { search: { type: '', q: '', match: 'all', conds: [] }, base: info.baseDN, sel: '', tab: '', selKind: '', cols: '', ldapOpen: false, filterError: '' };
  let shown = []; // DNs in the current results, lower-cased
  const gc = isGlobalCatalog(info);

  const writeUrl = () => {
    const p = new URLSearchParams();
    if (st.base.toLowerCase() !== info.baseDN.toLowerCase()) p.set('base', st.base);
    const f = toFilter(st.search, info.isAD);
    if (f !== '(objectClass=*)') p.set('filter', f);
    if (st.cols) p.set('cols', st.cols);
    if (st.sel) p.set('sel', st.sel);
    if (st.tab) p.set('tab', st.tab);
    history.replaceState(null, '', '#/dir' + (p.toString() ? '?' + p : ''));
  };

  // ---- sidebar: saved views and folders
  const tree = new Tree(roots.includes(info.baseDN) ? roots : [info.baseDN, ...roots], (dn) => {
    st.base = dn;
    st.sel = '';
    changed();
  }, { foldersOnly: true });
  const views = h('ul', { class: 'views-list' }, presets.filter((p) => info.isAD || !p.ad).map((p) => {
    // The Global Catalog never returns what some views test: offer them
    // greyed out with the reason, rather than let them show 0.
    if (gc && presetBlind(p)) {
      return h('li', null, h('button', { type: 'button', disabled: true, title: gcNote(info) }, p.label, h('span', { class: 'view-note' }, gcNote(info))));
    }
    return h('li', null, h('button', { type: 'button', onclick: () => {
      st.search = { type: '', q: '', match: 'all', conds: [], ...structuredClone(p.search) };
      st.sel = '';
      syncControls();
      changed();
    } }, p.label));
  }));
  const sidebar = h('aside', { class: 'dir-side', 'aria-label': 'Views and folders' },
    h('div', { class: 'side-title' }, 'Views'), views,
    h('div', { class: 'side-title' }, 'Folders'), tree.el);

  // ---- search box, type tabs and chips
  const q = h('input', { type: 'search', class: 'dir-q', placeholder: 'Search by name, login or email', 'aria-label': 'Search the directory' });
  q.addEventListener('input', debounce(() => { st.search.q = q.value; changed(); }, 300));
  const typeTabs = h('div', { class: 'seg', role: 'tablist', 'aria-label': 'Kind' });
  const chips = h('div', { class: 'chips' });
  const editor = h('div', { class: 'chip-editor', hidden: true });
  const ldapText = h('textarea', { class: 'mono', rows: 3, spellcheck: 'false', 'aria-label': 'LDAP filter' });
  const colsInput = h('input', { class: 'mono', placeholder: 'e.g. department,title', 'aria-label': 'Extra columns' });
  const ldapMsg = h('div', { class: 'hint error-text', 'aria-live': 'polite' });
  const ldapBox = h('div', { class: 'ldap-box', hidden: true },
    h('label', null, h('span', null, 'LDAP filter'), ' ', h('span', { class: 'muted' }, '· edit it or paste one; the filters above follow')), ldapText,
    h('label', { class: 'ldap-cols' }, h('span', null, 'Extra columns'), colsInput),
    h('div', { class: 'ldap-actions' }, ldapMsg, h('span', { class: 'spacer' }),
      h('button', { type: 'button', class: 'primary', onclick: () => applyLdap() }, 'Apply')));
  const ldapToggle = h('button', { type: 'button', class: 'link-btn', onclick: () => { st.ldapOpen = !st.ldapOpen; syncControls(); } });

  const applyLdap = () => {
    try {
      st.search = fromFilter(ldapText.value.trim() || '(objectClass=*)');
      st.cols = colsInput.value.split(',').map((s) => s.trim()).filter(Boolean).join(',');
      ldapMsg.textContent = '';
      syncControls();
      changed();
    } catch (err) {
      ldapMsg.textContent = 'Not a valid filter: ' + err.message;
    }
  };

  const addCond = (c) => { st.search.conds.push(c); editor.hidden = true; syncControls(); changed(); };

  const openEditor = (k) => {
    editor.hidden = false;
    const cancel = h('button', { type: 'button', onclick: () => { editor.hidden = true; } }, 'Cancel');
    if (k === 'group') {
      const id = 'dir-groups';
      const list = h('datalist', { id });
      allGroups().then((gs) => list.replaceChildren(...gs.map((g) => h('option', { value: g.name }, g.dn))));
      const input = h('input', { list: id, placeholder: 'Group name', 'aria-label': 'Group', autocomplete: 'off' });
      const nested = h('input', { type: 'checkbox', checked: true });
      const msg = h('span', { class: 'hint error-text' });
      const add = async () => {
        const v = input.value.trim();
        const gs = await allGroups();
        const hit = gs.filter((g) => g.name.toLowerCase() === v.toLowerCase() || g.dn.toLowerCase() === v.toLowerCase());
        if (hit.length !== 1) { msg.textContent = hit.length ? 'Several groups have that name; paste the full path (DN)' : 'No group called ' + v; return; }
        addCond({ k: 'group', dn: hit[0].dn, nested: info.isAD && nested.checked });
      };
      input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
      editor.replaceChildren(h('b', null, 'In group'), list, input,
        info.isAD ? h('label', { class: 'check' }, nested, ' include sub-groups') : null,
        h('button', { type: 'button', class: 'primary', onclick: add }, 'Add'), cancel, msg);
      input.focus();
    } else if (k === 'idle') {
      const days = h('input', { type: 'number', min: 1, value: 90, class: 'days', 'aria-label': 'Days' });
      editor.replaceChildren(h('b', null, 'Not logged in for'), days, 'days',
        h('button', { type: 'button', class: 'primary', onclick: () => addCond({ k: 'idle', days: Math.max(1, Number(days.value) || 90) }) }, 'Add'), cancel);
      days.focus();
    } else if (k === 'field') {
      const id = 'dir-fields';
      const attr = h('input', { list: id, placeholder: 'Field, e.g. department', 'aria-label': 'Field', class: 'mono', autocomplete: 'off' });
      const op = h('select', { 'aria-label': 'Comparison' }, Object.entries(fieldOpLabels).map(([v, l]) => h('option', { value: v }, l)));
      const value = h('input', { placeholder: 'Value', 'aria-label': 'Value' });
      op.addEventListener('change', () => { value.hidden = op.value === 'has' || op.value === 'missing'; });
      const add = () => {
        if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(attr.value.trim())) { attr.focus(); return; }
        addCond({ k: 'field', attr: attr.value.trim(), op: op.value, value: value.hidden ? '' : value.value });
      };
      editor.replaceChildren(h('datalist', { id }, commonFields.map((f) => h('option', { value: f }))), attr, op, value,
        h('button', { type: 'button', class: 'primary', onclick: add }, 'Add'), cancel);
      attr.focus();
    }
  };

  const addMenu = h('details', { class: 'menu' }, h('summary', { class: 'add-filter' }, '+ Add filter'),
    h('div', { class: 'menu-pop', role: 'menu' }, Object.entries(kinds).filter(([k, d]) => d.menu && (info.isAD || !d.ad)).map(([k, d]) => {
      const blind = gc && gcBlindKind(k);
      return h('button', { type: 'button', role: 'menuitem', disabled: blind, onclick: () => {
        addMenu.open = false;
        if (k === 'group' || k === 'idle' || k === 'field') openEditor(k);
        else addCond(k === 'disabled' ? { k, not: false } : { k });
      } }, h('span', null, d.menu), h('span', { class: blind ? 'warn-text' : 'muted' }, blind ? gcNote(info) : d.hint));
    })));
  document.addEventListener('click', (ev) => { if (addMenu.open && !addMenu.contains(ev.target)) addMenu.open = false; });

  const matchSel = h('select', { 'aria-label': 'Combine filters', onchange: (ev) => { st.search.match = ev.target.value; changed(); } },
    h('option', { value: 'all' }, 'Match all filters'), h('option', { value: 'any' }, 'Match any filter'));

  // syncControls redraws the controls from st (not the results).
  const syncControls = () => {
    if (q.value !== st.search.q) q.value = st.search.q;
    typeTabs.replaceChildren(...[['', 'Everything'], ...Object.entries(types).filter(([id]) => info.isAD || id !== 'computers').map(([id, t]) => [id, t.label])].map(([id, label]) =>
      h('button', { type: 'button', role: 'tab', 'aria-selected': String(st.search.type === id), class: st.search.type === id ? 'on' : '',
        onclick: () => { st.search.type = id; syncControls(); changed(); } }, label)));
    chips.replaceChildren(...st.search.conds.map((c, i) => {
      const [field, value] = chipWords(c);
      return h('span', { class: 'chip' + (c.k === 'raw' ? ' raw' : ''), title: kinds[c.k].clause(c, Date.now()) },
        h('span', { class: 'chip-field' }, field), value ? h('b', null, value) : null,
        h('button', { type: 'button', class: 'chip-x', 'aria-label': 'Remove filter ' + field, onclick: () => { st.search.conds.splice(i, 1); syncControls(); changed(); } }, '×'));
    }), ...nodes(addMenu, st.search.conds.length > 1 ? matchSel : null));
    matchSel.value = st.search.match;
    ldapBox.hidden = !st.ldapOpen;
    ldapToggle.textContent = st.ldapOpen ? 'Hide LDAP filter' : 'Edit as LDAP filter';
    ldapText.value = toFilter(st.search, info.isAD);
    colsInput.value = st.cols;
  };

  // ---- results
  const count = h('div', { class: 'dir-count', 'aria-live': 'polite' });
  const exportMenu = h('details', { class: 'menu export' }, h('summary', { class: 'button' }, 'Export ▾'), h('div', { class: 'menu-pop right' }));
  const results = h('div', { class: 'dir-results' });
  const gcWarn = h('div', { class: 'dir-gc', 'aria-live': 'polite' });

  const listing = () => !st.search.type && !st.search.q.trim() && !st.search.conds.length;

  const run = async () => {
    const current = claim(results);
    results.replaceChildren(loading(listing() ? 'Loading folder…' : 'Searching…'));
    count.replaceChildren();
    gcWarn.replaceChildren();
    try {
      let rows, cols, truncated;
      if (listing()) {
        const res = await api.children(st.base);
        rows = res.items.map((o) => ({ ...o, attributes: [] }));
        truncated = res.truncated;
        cols = [['Kind', kindWord], ['Description', (e) => e.description || '']];
      } else {
        const spec = columnsFor(st.search.type, info.isAD);
        const extra = st.cols ? st.cols.split(',') : [];
        const res = await api.search({ base: st.base, filter: toFilter(st.search, info.isAD), attrs: [...new Set([...spec.attrs, ...extra])].join(','), limit, scope: 'sub' });
        rows = res.entries.sort((a, b) => displayName(a).localeCompare(displayName(b), undefined, { sensitivity: 'base' }));
        truncated = res.truncated;
        cols = [...spec.cols, ...extra.map((a) => [a, (e) => text(e, a), 'mono'])];
      }
      if (!current()) return;
      shown = rows.map((r) => r.dn.toLowerCase());
      drawGcWarnings(rows);
      drawResults(rows, cols, truncated);
      drawPanel();
    } catch (err) {
      if (current()) results.replaceChildren(errorBox(err));
    }
  };

  // drawGcWarnings says when a Global Catalog result can't be trusted.
  const drawGcWarnings = (rows) => {
    const lines = [gcSearchWarning(info, st.search), gcGroupsWarning(info, rows)].filter(Boolean);
    gcWarn.replaceChildren(...lines.map((t) => h('div', { class: 'callout warn' }, t)));
  };

  const drawResults = (rows, cols, truncated) => {
    const where = ouPath(st.base) || st.base.split(',').filter((r) => /^dc=/i.test(r)).map((r) => r.slice(3)).join('.') || st.base;
    count.replaceChildren(...nodes(h('b', null, truncated ? `${limit}+` : String(rows.length)), ' ',
      listing() ? `in ${where}` : rows.length === 1 ? 'result' : 'results',
      truncated ? h('span', { class: 'muted' }, ' — showing the first ' + limit + '; add a filter to narrow it') : null));
    const header = ['Name', ...cols.map((c) => c[0]), 'Folder'];
    const cellsOf = (e) => [displayName(e), ...cols.map((c) => c[1](e)), containerPath(e.dn) || '—'];
    exportMenu.querySelector('.menu-pop').replaceChildren(
      h('button', { type: 'button', onclick: () => { exportMenu.open = false; downloadCSV('directory.csv', [...header, 'dn'], rows.map((e) => [...cellsOf(e).map(cellText), e.dn])); } },
        `These ${plural(rows.length, 'row')} (CSV)`));
    if (!rows.length) {
      results.replaceChildren(h('div', { class: 'empty' }, listing() ? 'This folder is empty.' : 'Nothing matches. Remove a filter, or select someone in the tree to see why they aren’t here.'));
      return;
    }
    results.replaceChildren(h('div', { class: 'table-scroll' }, h('table', { class: 'dir-table', 'aria-label': 'Results' },
      h('thead', null, h('tr', null, header.map((t, i) => h('th', { class: cols[i - 1]?.[2] === 'num' ? 'num' : null }, t)))),
      h('tbody', null, rows.map((e) => {
        const [name, ...rest] = cellsOf(e);
        const tr = h('tr', { class: 'clickable' + (e.dn.toLowerCase() === st.sel.toLowerCase() ? ' sel' : ''), tabindex: 0 },
          h('td', null, h('span', { class: 'namecell' }, kindBadge(e.kind, e.dn), h('span', { class: 'name' }, name),
            isDisabled(e) && !cols.some((c) => c[0] === 'Status') ? h('span', { class: 'status off' }, 'Disabled') : null)),
          rest.map((v, i) => h('td', { class: [cols[i]?.[2], i === rest.length - 1 ? 'muted' : ''].filter(Boolean).join(' ') || null }, v)));
        const open = () => {
          if (listing() && e.kind === 'container') { st.base = e.dn; st.sel = ''; tree.reveal(e.dn); changed(); return; }
          st.sel = e.dn; st.selKind = e.kind; st.tab = '';
          for (const r of tr.parentNode.children) r.classList.toggle('sel', r === tr);
          writeUrl();
          drawPanel();
        };
        tr.addEventListener('click', open);
        tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') open(); });
        return tr;
      })))));
  };

  // ---- details panel
  const panelBody = h('div');
  const whyBox = h('div', { class: 'panel-why' });
  const panel = h('aside', { class: 'dir-panel', 'aria-label': 'Details', hidden: true },
    h('button', { type: 'button', class: 'icon-btn panel-close', 'aria-label': 'Close details', onclick: () => { st.sel = ''; writeUrl(); drawPanel(); for (const r of results.querySelectorAll('tr.sel')) r.classList.remove('sel'); } }, '×'),
    panelBody);
  let panelFor = '';

  const drawPanel = () => {
    panel.hidden = !st.sel;
    if (!st.sel) { panelFor = ''; return; }
    const missing = !listing() && !shown.includes(st.sel.toLowerCase());
    whyBox.replaceChildren();
    claim(whyBox);
    if (missing && (st.selKind === 'user' || st.selKind === '')) {
      runExplain(whyBox, { who: st.sel, filter: toFilter(st.search, info.isAD), base: st.base, compact: true });
    }
    if (panelFor === st.sel) return;
    panelFor = st.sel;
    renderEntry(panelBody, st.sel, st.tab, { onTab: (id) => { st.tab = id; writeUrl(); }, compact: true, after: whyBox, info });
  };

  const changed = () => { writeUrl(); run(); };

  const el = h('div', { class: 'dir' },
    sidebar,
    h('section', { class: 'dir-main' },
      q,
      h('div', { class: 'dir-bar' }, typeTabs, h('span', { class: 'spacer' }), ldapToggle),
      chips, editor, ldapBox,
      h('div', { class: 'dir-status' }, count, h('span', { class: 'spacer' }), exportMenu),
      gcWarn, results),
    panel);
  document.addEventListener('click', (ev) => { if (exportMenu.open && !exportMenu.contains(ev.target)) exportMenu.open = false; });

  const root = tree.nodes.get(info.baseDN.toLowerCase());
  if (root) tree.expand(root);

  return {
    el,
    restoreUrl: writeUrl,
    // show applies a URL: #/dir?base=&filter=&cols=&sel=&tab=
    show(params) {
      st.base = params.get('base') || info.baseDN;
      st.cols = params.get('cols') || '';
      st.sel = params.get('sel') || '';
      st.tab = params.get('tab') || '';
      st.selKind = '';
      try {
        st.search = fromFilter(params.get('filter') || '(objectClass=*)');
      } catch (err) {
        st.search = { type: '', q: '', match: 'all', conds: [] };
        st.ldapOpen = true;
        ldapMsg.textContent = 'Not a valid filter: ' + err.message;
      }
      tree.reveal(st.base);
      syncControls();
      panelFor = '';
      writeUrl();
      run();
    },
  };
}

// directoryParams maps the old Browse, Groups and Search URLs onto Directory's.
export function directoryParams(view, params, info) {
  const p = new URLSearchParams();
  if (view === 'browse') {
    const dn = params.get('dn');
    if (dn && dn.toLowerCase() !== info.baseDN.toLowerCase()) {
      p.set('base', splitDN(dn).slice(1).join(',') || info.baseDN);
      p.set('sel', dn);
      if (params.get('tab')) p.set('tab', params.get('tab'));
    }
  } else if (view === 'groups') {
    p.set('filter', toFilter({ type: 'groups' }, info.isAD));
  } else if (view === 'search') {
    for (const k of ['base', 'filter']) if (params.get(k)) p.set(k, params.get(k));
    if (params.get('attrs')) p.set('cols', params.get('attrs'));
  }
  return p;
}

