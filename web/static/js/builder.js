import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, copyButton, rdnValue, claim } from './dom.js';
import { buildSettings, defaultOptions, accountClasses, groupSchemas } from './filters.js';
import { prefillLoginTest } from './logintest.js';
import { plural } from './format.js';

const storageKey = 'ldap-console.filter-builder';
const loginAttrs = ['sAMAccountName', 'userPrincipalName', 'mail', 'uid', 'cn'];

function loadOptions(isAD) {
  const o = defaultOptions(isAD);
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || '{}');
    for (const k of Object.keys(o)) if (k in saved && typeof saved[k] === typeof o[k]) o[k] = saved[k];
  } catch { /* storage unavailable or corrupt: defaults */ }
  return o;
}

function saveOptions(o) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(o));
  } catch { /* storage unavailable: the builder still works */ }
}

// groupPicker edits a list of group DNs. Entries are picked by name or DN
// from the directory's group list, or pasted as a DN.
function groupPicker(list, groupsReady, datalistId, onChange) {
  const chips = h('div', { class: 'chips' });
  const input = h('input', { list: datalistId, class: 'mono', placeholder: 'Group name or DN, then Enter', autocomplete: 'off', 'aria-label': 'Add group' });
  const msg = h('span', { class: 'hint error-text' });

  const draw = () => {
    chips.replaceChildren(...list.map((dn, i) => h('span', { class: 'chip', title: dn },
      kindBadge('group'), entryLink(dn, rdnValue(dn)),
      h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Remove ' + rdnValue(dn),
        onclick: () => { list.splice(i, 1); draw(); onChange(); } }, '×'))));
  };

  const add = async () => {
    const v = input.value.trim();
    msg.textContent = '';
    if (!v) return;
    const groups = await groupsReady;
    const lower = v.toLowerCase();
    let dn = groups.find((g) => g.dn.toLowerCase() === lower)?.dn;
    if (!dn) {
      const byName = groups.filter((g) => g.name.toLowerCase() === lower);
      if (byName.length > 1) { msg.textContent = `${byName.length} groups are called ${v}; pick one by its DN`; return; }
      dn = byName[0]?.dn;
    }
    if (!dn && /^[A-Za-z][\w-]*=/.test(v)) dn = v; // a DN outside the listed groups
    if (!dn) { msg.textContent = `No group named ${v}`; return; }
    if (!list.some((d) => d.toLowerCase() === dn.toLowerCase())) list.push(dn);
    input.value = '';
    draw();
    onChange();
  };
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
  input.addEventListener('change', add);
  draw();
  return h('div', { class: 'picker' }, chips, input, msg);
}

function field(label, control, hint) {
  return h('label', { class: 'field' }, h('span', null, label), control, hint ? h('span', { class: 'muted hint' }, hint) : null);
}

function check(label, checked, onchange, hint) {
  return h('label', { class: 'check', title: hint || null }, h('input', { type: 'checkbox', checked, onchange }), ' ', label);
}

// settingsCard shows one application's settings with copy buttons and a
// hand-off to the login test, prefilled with exactly these values.
function settingsCard(title, app, rows, values) {
  return h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('b', null, title), h('span', { class: 'spacer' }),
      h('button', { type: 'button', onclick: () => { prefillLoginTest(app, values); location.hash = '#/test?app=' + app; } }, 'Try in Login test')),
    rows.filter(([, v]) => v !== undefined).map(([label, v]) => h('div', { class: 'setting' },
      h('span', { class: 'muted' }, label),
      v ? h('code', null, v) : h('span', { class: 'muted' }, '(leave empty)'),
      v ? copyButton(v) : null)));
}

// renderBuilder composes user and group filters for an application's LDAP
// login from a few choices: who the accounts are, how they log in, which
// groups may log in, and which are admins.
export async function renderBuilder(el, params, info) {
  const o = loadOptions(info.isAD);
  const fromHash = params.getAll('group');
  if (fromHash.length) o.groups = fromHash; // handed over from People → groups
  const groupsReady = api.groups().then((r) => r.items).catch(() => []);
  const datalistId = 'builder-groups';
  const datalist = h('datalist', { id: datalistId });
  groupsReady.then((gs) => datalist.replaceChildren(...gs.map((g) => h('option', { value: g.dn }, g.name))));

  const out = h('div', { class: 'builder-out' });
  const preview = h('div');
  const update = () => {
    saveOptions(o);
    claim(preview); // a running preview is for the old filter
    preview.replaceChildren();
    const s = buildSettings(o);
    out.replaceChildren(...nodes(
      s.warnings.map((w) => h('div', { class: 'notice warn-text' }, '! ', w)),
      settingsCard('Generic', 'generic', [
        ['User search base', s.generic.userBase], ['User filter', s.generic.userFilter],
        ['Group search base', s.generic.groupBase], ['Group filter', s.generic.groupFilter]], s.generic),
      settingsCard('Gitea (LDAP via BindDN)', 'gitea', [
        ['User Search Base', s.gitea.userBase], ['User Filter', s.gitea.userFilter],
        ['Admin Filter', s.gitea.adminFilter], ['Email Attribute', s.gitea.emailAttr]], s.gitea),
      settingsCard('Open WebUI', 'openwebui', [
        ['LDAP_SEARCH_BASE', s.openwebui.userBase], ['LDAP_ATTRIBUTE_FOR_USERNAME', s.openwebui.usernameAttr],
        ['LDAP_ATTRIBUTE_FOR_MAIL', s.openwebui.emailAttr], ['LDAP_SEARCH_FILTERS', s.openwebui.searchFilters]], s.openwebui),
      h('div', { class: 'card' },
        h('div', { class: 'card-head' }, h('b', null, 'Who could log in'), h('span', { class: 'spacer' }),
          h('button', { type: 'button', class: 'primary', onclick: () => runPreview(preview, s.preview, o, info) }, 'List matching accounts')),
        h('div', { class: 'setting' }, h('span', { class: 'muted' }, 'Filter'), h('code', null, s.preview), copyButton(s.preview)),
        preview)));
  };
  const set = (k) => (ev) => { o[k] = ev.target.type === 'checkbox' ? ev.target.checked : ev.target.value.trim(); update(); };

  const accounts = h('select', { onchange: set('accounts') },
    Object.entries(accountClasses).map(([k, a]) => h('option', { value: k, selected: o.accounts === k }, a.label)));
  const loginList = h('datalist', { id: 'builder-login-attrs' }, loginAttrs.map((a) => h('option', { value: a })));
  const schema = h('select', { onchange: set('groupSchema') },
    Object.entries(groupSchemas).map(([k, g]) => h('option', { value: k, selected: o.groupSchema === k }, g.label)));

  const form = h('form', { class: 'logintest', onsubmit: (ev) => ev.preventDefault() },
    h('h1', null, 'Filter builder'),
    h('p', { class: 'muted' }, 'Composes the user and group filters for an application\'s LDAP login. Pick who may log in; copy the result or try it in the login test.'),
    datalist, loginList,
    h('fieldset', null, h('legend', null, 'Accounts'),
      field('Account type', accounts),
      field('Login attribute', h('input', { class: 'mono', list: 'builder-login-attrs', value: o.loginAttr, onchange: set('loginAttr') }),
        'What users type to log in: sAMAccountName (jdoe), userPrincipalName (jdoe@corp.local), mail or uid'),
      field('Email attribute', h('input', { class: 'mono', value: o.emailAttr, onchange: set('emailAttr') })),
      field('User search base', h('input', { class: 'mono', value: o.userBase, placeholder: info.baseDN, onchange: set('userBase') }), 'Empty = the base DN of this connection'),
      check('Exclude disabled accounts (AD)', o.excludeDisabled, set('excludeDisabled')),
      check('Require an email address', o.requireEmail, set('requireEmail'), 'Gitea and Open WebUI need one to create the account')),
    h('fieldset', null, h('legend', null, 'Who may log in'),
      field('Members of any of these groups', groupPicker(o.groups, groupsReady, datalistId, update), 'No groups = every account above'),
      check('Count nested group members (AD)', o.nested, set('nested'),
        'Uses LDAP_MATCHING_RULE_IN_CHAIN, so members of sub-groups match too'),
      field('Admins: members of any of these groups', groupPicker(o.adminGroups, groupsReady, datalistId, update), 'Gitea\'s Admin Filter')),
    h('fieldset', null, h('legend', null, 'Group lookup (generic apps)'),
      field('Group schema', schema),
      field('Group search base', h('input', { class: 'mono', value: o.groupBase, placeholder: info.baseDN, onchange: set('groupBase') }))));

  el.replaceChildren(h('div', { class: 'page' }, h('div', { class: 'logintest-wrap' }, form, out)));
  update();
}

async function runPreview(el, filter, o, info) {
  const current = claim(el);
  el.replaceChildren(loading('Searching…'));
  try {
    const res = await api.search({ base: o.userBase || info.baseDN, filter, attrs: [o.loginAttr, o.emailAttr].filter(Boolean).join(','), limit: 1000 });
    if (!current()) return;
    const attrOf = (e, name) => e.attributes.find((a) => a.name.toLowerCase() === name.toLowerCase())?.values[0]?.text || '';
    el.replaceChildren(...nodes(
      h('div', { class: 'step-msg' }, h('b', null, plural(res.entries.length, 'account')), res.truncated ? ' (first 1000 shown)' : '',
        res.entries.length ? '' : '. Nobody could log in: check the groups, the account type and the search base'),
      res.entries.length ? h('ul', { class: 'step-items' }, res.entries.map((e) => h('li', null,
        kindBadge(e.kind, e.dn), entryLink(e.dn, rdnValue(e.dn)),
        h('span', { class: 'mono muted' }, attrOf(e, o.loginAttr)), h('span', { class: 'muted' }, attrOf(e, o.emailAttr))))) : null));
  } catch (err) {
    if (current()) el.replaceChildren(errorBox(err));
  }
}
