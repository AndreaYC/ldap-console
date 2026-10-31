import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, copyButton, claim, term, plainTerm } from './dom.js';
import { loginSummary } from './format.js';

// Field sets per application: [key, label, hint, AD default, non-AD default].
// A label is a glossary key, or [plain, the app's own setting name] so values
// can be copied over.
const apps = {
  generic: {
    label: 'Generic',
    fields: [
      ['userBase', 'userBase', 'Empty = wherever this connection searches'],
      ['userFilter', 'userFilter', '{username} = what the user types (%s and %[1]s work too)',
        '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))', '(&(objectClass=inetOrgPerson)(uid={username}))'],
      ['groupBase', 'groupBase', 'Empty = wherever this connection searches'],
      ['groupFilter', 'groupFilter', '{dn} = the user\'s full path, {username} = what they type. Empty = skip',
        '(&(objectClass=group)(member={dn}))', '(&(objectClass=groupOfNames)(member={dn}))'],
    ],
  },
  gitea: {
    label: 'Gitea',
    fields: [
      ['userBase', 'userBase', ''],
      ['userFilter', 'userFilter', '%[1]s = what the user types',
        '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%[1]s))', '(&(objectClass=inetOrgPerson)(uid=%[1]s))'],
      ['adminFilter', 'adminFilter', 'Optional'],
      ['restrictedFilter', 'restrictedFilter', 'Optional'],
      ['emailAttr', 'emailAttr', '', 'mail', 'mail'],
      ['groupBase', ['Where to look for groups', 'Group Search Base DN'], 'Empty = group check off'],
      ['groupMemberAttr', 'groupMemberAttr', '', 'member', 'member'],
      ['userAttrInGroup', 'userAttrInGroup', 'Empty = the user\'s full path (DN)'],
      ['groupFilter', 'verifyGroups', 'Optional, e.g. (|(cn=gitea-users)(cn=gitea-admins))'],
    ],
  },
  openwebui: {
    label: 'Open WebUI',
    fields: [
      ['userBase', ['Where to look for users', 'LDAP_SEARCH_BASE'], ''],
      ['usernameAttr', ['What users type to log in', 'LDAP_ATTRIBUTE_FOR_USERNAME'], 'jdoe is sAMAccountName on AD, uid elsewhere', 'sAMAccountName', 'uid'],
      ['emailAttr', ['Where the email address is', 'LDAP_ATTRIBUTE_FOR_MAIL'], '', 'mail', 'mail'],
      ['searchFilters', ['Extra conditions', 'LDAP_SEARCH_FILTERS'], 'e.g. (memberOf=CN=ai-users,OU=Groups,…)'],
      ['groupAttr', ['Account field that lists its groups', 'LDAP_ATTRIBUTE_FOR_GROUPS'], 'Only with group management on'],
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

// prefillLoginTest stores settings for app's form, e.g. from the filter
// builder; fields it does not mention keep their saved values.
export function prefillLoginTest(app, values) {
  save(app, { ...loadSaved(app), ...values });
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
export function renderLoginTest(el, info, params) {
  let app = Object.hasOwn(apps, params?.get('app') || '') ? params.get('app') : 'generic';
  const appSelect = h('select', { 'aria-label': 'Application' },
    Object.entries(apps).map(([k, a]) => h('option', { value: k, selected: k === app }, a.label)));
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
      return h('label', { class: 'field' }, h('span', null, Array.isArray(label) ? plainTerm(...label) : term(label)), inputs[key], hint ? h('span', { class: 'muted hint' }, hint) : null);
    }));
  };
  appSelect.addEventListener('change', () => { app = appSelect.value; drawFields(); claim(out); out.replaceChildren(placeholder()); });

  const submit = async (ev) => {
    ev.preventDefault();
    const values = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value.trim()]));
    save(app, values);
    // A slow earlier test must not overwrite a newer one or a switched app.
    const current = claim(out);
    const label = apps[app].label;
    out.replaceChildren(loading('Testing…'));
    try {
      const res = await api.checkLogin({ app, username: username.value.trim(), password: password.value, ...values });
      if (!current()) return;
      const sum = loginSummary(res.steps, label);
      out.replaceChildren(
        h('div', { class: 'summary ' + sum.status }, h('span', { class: 'mark' }, statusMark[sum.status]), sum.text),
        h('div', { class: 'steps' }, res.steps.map(renderStep)));
    } catch (err) {
      if (current()) out.replaceChildren(errorBox(err));
    }
  };

  const form = h('form', { class: 'logintest', onsubmit: submit },
    h('h1', null, 'Login test'),
    h('p', { class: 'muted' }, 'Replays an application\'s LDAP login for one user, so you can see which setting is wrong before you save it there. ',
      'Need the filters first? Use the ', h('a', { href: '#/filters' }, 'filter builder'), '.'),
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
