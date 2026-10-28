import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, copyButton } from './dom.js';
import { loginSummary } from './format.js';

// Field sets per application: [key, label, hint, AD default, non-AD default].
// Placeholder hints name each app's own setting so values can be copied over.
const apps = {
  generic: {
    label: 'Generic',
    fields: [
      ['userBase', 'User search base', 'Empty = the base DN of this connection'],
      ['userFilter', 'User filter', '{username} = the login name (%s and %[1]s work too)',
        '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))', '(&(objectClass=inetOrgPerson)(uid={username}))'],
      ['groupBase', 'Group search base', 'Empty = the base DN of this connection'],
      ['groupFilter', 'Group filter', '{dn} = the user\'s DN, {username} = the login name. Empty = skip',
        '(&(objectClass=group)(member={dn}))', '(&(objectClass=groupOfNames)(member={dn}))'],
    ],
  },
  gitea: {
    label: 'Gitea',
    fields: [
      ['userBase', 'User Search Base', ''],
      ['userFilter', 'User Filter', '%[1]s = the login name',
        '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%[1]s))', '(&(objectClass=inetOrgPerson)(uid=%[1]s))'],
      ['adminFilter', 'Admin Filter', 'Optional'],
      ['restrictedFilter', 'Restricted Filter', 'Optional'],
      ['emailAttr', 'Email Attribute', '', 'mail', 'mail'],
      ['groupBase', 'Group Search Base DN', 'Empty = group verification off'],
      ['groupMemberAttr', 'Group Attribute Containing List Of Users', '', 'member', 'member'],
      ['userAttrInGroup', 'User Attribute Listed In Group', 'Empty = the user\'s full DN'],
      ['groupFilter', 'Verify group membership filter', 'Optional, e.g. (|(cn=gitea-users)(cn=gitea-admins))'],
    ],
  },
  openwebui: {
    label: 'Open WebUI',
    fields: [
      ['userBase', 'Search Base', 'LDAP_SEARCH_BASE'],
      ['usernameAttr', 'Attribute for Username', 'LDAP_ATTRIBUTE_FOR_USERNAME', 'sAMAccountName', 'uid'],
      ['emailAttr', 'Attribute for Mail', 'LDAP_ATTRIBUTE_FOR_MAIL', 'mail', 'mail'],
      ['searchFilters', 'Search Filters', 'LDAP_SEARCH_FILTERS, e.g. (memberOf=CN=ai-users,OU=Groups,…)'],
      ['groupAttr', 'Attribute for Groups', 'LDAP_ATTRIBUTE_FOR_GROUPS, only with group management on'],
    ],
  },
};

const statusMark = { ok: '✓', warn: '!', fail: '✗', skipped: '–' };
const storageKey = (app) => 'ldap-console.login-test.' + app;

function loadSaved(app) {
  try {
    return JSON.parse(localStorage.getItem(storageKey(app)) || '{}');
  } catch {
    return {};
  }
}

function save(app, values) {
  try {
    localStorage.setItem(storageKey(app), JSON.stringify(values));
  } catch { /* storage unavailable: the form still works */ }
}

function renderStep(s) {
  return h('div', { class: 'step ' + s.status },
    h('div', { class: 'step-head' }, h('span', { class: 'mark' }, statusMark[s.status] || '?'), h('b', null, s.title)),
    h('div', { class: 'step-msg' }, s.message),
    ...nodes(
      s.filter ? h('div', { class: 'step-detail' }, h('span', { class: 'muted' }, 'Filter sent: '), h('code', null, s.filter), copyButton(s.filter)) : null,
      s.base ? h('div', { class: 'step-detail muted' }, 'Base: ', h('span', { class: 'mono' }, s.base)) : null,
      s.items?.length ? h('ul', { class: 'step-items' }, s.items.map((o) =>
        h('li', null, kindBadge(o.kind), entryLink(o.dn, o.name), o.disabled ? h('span', { class: 'tag' }, 'disabled') : null))) : null,
      s.truncated ? h('div', { class: 'notice' }, 'Only the first results are shown.') : null));
}

// renderLoginTest replays an application's LDAP login for one user.
export function renderLoginTest(el, info) {
  let app = 'generic';
  const appSelect = h('select', { 'aria-label': 'Application' },
    Object.entries(apps).map(([k, a]) => h('option', { value: k }, a.label)));
  const fieldsBox = h('div');
  const username = h('input', { name: 'test-username', placeholder: 'login name, e.g. jdoe', required: true, autocomplete: 'off' });
  const password = h('input', { name: 'test-password', type: 'password', autocomplete: 'new-password', placeholder: 'optional' });
  const placeholder = () => h('div', { class: 'empty' }, 'Results appear here, one line per step of the login.');
  const out = h('section', { class: 'logintest-results', 'aria-label': 'Results', 'aria-live': 'polite' }, placeholder());
  let inputs = {};

  const drawFields = () => {
    const saved = loadSaved(app);
    inputs = {};
    fieldsBox.replaceChildren(...apps[app].fields.map(([key, label, hint, adDefault, otherDefault]) => {
      const fallback = (info.isAD ? adDefault : otherDefault) || '';
      inputs[key] = h('input', { name: key, class: 'mono', value: saved[key] ?? fallback, autocomplete: 'off' });
      return h('label', { class: 'field' }, h('span', null, label), inputs[key], hint ? h('span', { class: 'muted hint' }, hint) : null);
    }));
  };
  appSelect.addEventListener('change', () => { app = appSelect.value; drawFields(); out.replaceChildren(placeholder()); });

  const submit = async (ev) => {
    ev.preventDefault();
    const values = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value.trim()]));
    save(app, values);
    out.replaceChildren(loading('Testing…'));
    try {
      const res = await api.checkLogin({ app, username: username.value.trim(), password: password.value, ...values });
      const sum = loginSummary(res.steps, apps[app].label);
      out.replaceChildren(
        h('div', { class: 'summary ' + sum.status }, h('span', { class: 'mark' }, statusMark[sum.status]), sum.text),
        h('div', { class: 'steps' }, res.steps.map(renderStep)));
    } catch (err) {
      out.replaceChildren(errorBox(err));
    }
  };

  const form = h('form', { class: 'logintest', onsubmit: submit },
    h('h1', null, 'Login test'),
    h('p', { class: 'muted' }, 'Replays an application\'s LDAP login for one user, so you can see which setting is wrong before you save it there.'),
    h('label', { class: 'field' }, h('span', null, 'Application'), appSelect),
    fieldsBox,
    h('div', { class: 'test-user' },
      h('label', { class: 'field' }, h('span', null, 'Test username'), username),
      h('label', { class: 'field' }, h('span', null, 'Password'), password,
        h('span', { class: 'muted hint' }, 'Optional. Used for one sign-in and never saved. A wrong password counts toward AD\'s lockout limit.'))),
    h('div', { class: 'toolbar' }, h('button', { type: 'submit', class: 'primary' }, 'Test login')));
  drawFields();
  el.replaceChildren(h('div', { class: 'page' }, h('div', { class: 'logintest-wrap' }, form, out)));
}
