import { api } from './api.js';
import { h, nodes, errorBox, loading, copyButton, claim, debounce, entryLink, rdnValue } from './dom.js';
import { appInfo, wizardDefaults, settingsFor, settingRows, copyAllText, checkPayload, needsGroups, forestHint } from './appsettings.js';
import { accountClasses } from './filters.js';
import { groupPicker } from './grouppicker.js';
import { renderStep } from './logintest.js';
import { ouPath } from './format.js';

const storageKey = 'ldap-console.app-login';
const stepLabels = ['Choose the app', 'Who can log in', 'Test with a person', 'Copy settings'];
const statusMark = { ok: '✓', warn: '!', fail: '✗' };

function load(isAD) {
  const st = wizardDefaults(isAD);
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || '{}');
    for (const k of Object.keys(st)) if (k in saved && typeof saved[k] === typeof st[k]) st[k] = saved[k];
  } catch { /* storage unavailable or corrupt: defaults */ }
  return st;
}

function save(st) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(st));
  } catch { /* storage unavailable: the wizard still works */ }
}

function radio(name, checked, onchange, label, hint) {
  return h('label', { class: 'choice' + (checked ? ' on' : '') },
    h('input', { type: 'radio', name, checked, onchange }),
    h('span', null, h('b', null, label), hint ? h('span', { class: 'muted' }, hint) : null));
}

function checkbox(checked, onchange, label, hint) {
  return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked, onchange }), h('span', null, label,
    hint ? h('span', { class: 'muted' }, ' ', hint) : null));
}

// sampleAccount fetches one real account so login choices can show what
// people would actually type.
function sampleAccount(isAD) {
  const filter = isAD ? '(&(objectCategory=person)(objectClass=user)(mail=*))' : '(&(objectClass=inetOrgPerson)(mail=*))';
  return api.search({ filter, attrs: 'sAMAccountName,userPrincipalName,mail,uid', limit: 1 })
    .then((r) => {
      const e = r.entries[0];
      const v = (n) => e?.attributes.find((a) => a.name.toLowerCase() === n.toLowerCase())?.values[0]?.text || '';
      return { sAMAccountName: v('sAMAccountName'), userPrincipalName: v('userPrincipalName'), mail: v('mail'), uid: v('uid') };
    })
    .catch(() => ({}));
}

// organisationalUnits lists the folders accounts can be searched in.
function organisationalUnits() {
  return api.search({ filter: '(|(objectClass=organizationalUnit)(objectClass=container))', attrs: 'ou', limit: 2000 })
    .then((r) => r.entries.map((e) => e.dn).sort((a, b) => ouPath(a).localeCompare(ouPath(b))))
    .catch(() => []);
}

// verdict sums a login test up in one plain sentence about the person.
function verdict(steps, name, app) {
  if (steps.some((s) => s.status === 'fail')) return { status: 'fail', text: `${name} can\u2019t log in to ${app}` };
  const warnings = steps.filter((s) => s.status === 'warn').length;
  const note = steps.some((s) => s.id === 'bind' && s.status === 'skipped') ? 'Password not tested' : '';
  if (warnings) return { status: 'warn', text: `${name} can log in to ${app}, with ${warnings === 1 ? 'a warning' : warnings + ' warnings'}`, note };
  return { status: 'ok', text: `${name} can log in to ${app}`, note };
}

// renderAppLogin walks through setting up an application's LDAP login:
// pick the app, say who may log in, test a real person, copy the settings.
export function renderAppLogin(el, params, info) {
  const st = load(info.isAD);
  const handed = params.getAll('group');
  if (handed.length) { // from People → groups
    Object.assign(st, { who: 'groups', groups: handed, step: 2 });
    history.replaceState(null, '', '#/app');
  }
  if (!Object.hasOwn(appInfo, st.app)) st.app = 'gitea';
  const sample = sampleAccount(info.isAD);
  const ous = organisationalUnits();
  const domain = info.baseDN.split(',').filter((r) => /^dc=/i.test(r)).map((r) => r.slice(3)).join('.') || info.baseDN;

  const stepper = h('ol', { class: 'stepper', 'aria-label': 'Steps' });
  const body = h('div', { class: 'wizard-body' });
  const footer = h('div', { class: 'wizard-foot' });
  const preview = h('div', { 'aria-live': 'polite' });
  const settings = () => settingsFor(st);
  let lastPeople = []; // the preview's accounts, offered as people to test

  // Steps 3 and 4 produce settings, so they wait until a group restriction
  // names a group: without one the settings would let everyone in.
  let groupWarning = false;
  const go = (n) => {
    n = Math.min(4, Math.max(1, n));
    groupWarning = n > 2 && needsGroups(st);
    st.step = groupWarning ? 2 : n;
    save(st);
    draw();
  };

  // The preview searches for everyone the current settings let in.
  const refreshPreview = debounce(async () => {
    const current = claim(preview);
    if (needsGroups(st)) {
      lastPeople = [];
      preview.replaceChildren(h('p', { class: 'muted' }, 'Add at least one group to see who can log in.'));
      return;
    }
    const s = settings();
    preview.replaceChildren(loading('Counting…'));
    try {
      const res = await api.search({ base: st.userBase || info.baseDN, filter: s.preview, attrs: [st.loginAttr, st.emailAttr].filter(Boolean).join(','), limit: 1000 });
      if (!current()) return;
      const n = res.entries.length;
      lastPeople = res.entries;
      preview.replaceChildren(...nodes(
        h('div', { class: 'big-count' }, res.truncated ? '1000+' : String(n), h('span', null, n === 1 ? ' person can log in' : ' people can log in')),
        n ? h('ul', { class: 'people' }, res.entries.slice(0, 8).map((e) => h('li', null,
          h('span', { class: 'avatar', 'aria-hidden': 'true' }, rdnValue(e.dn).slice(0, 1).toUpperCase()), entryLink(e.dn, rdnValue(e.dn))))) : null,
        n > 8 ? h('a', { href: '#/search?filter=' + encodeURIComponent(s.preview) }, `See all ${res.truncated ? '1000+' : n}`) : null,
        n ? null : h('p', { class: 'muted' }, 'Nobody matches yet. Check the groups, or open More options.')));
    } catch (err) {
      if (current()) preview.replaceChildren(errorBox(err));
    }
  }, 300);
  const changed = () => { save(st); refreshPreview(); };

  const stepApp = () => h('div', { class: 'step-pane' },
    h('h2', null, 'Which app are you connecting?'),
    h('div', { class: 'app-cards', role: 'radiogroup', 'aria-label': 'App' }, Object.entries(appInfo).map(([id, a]) =>
      h('label', { class: 'app-card' + (st.app === id ? ' on' : '') },
        h('input', { type: 'radio', name: 'app', checked: st.app === id, onchange: () => { st.app = id; changed(); draw(); } }),
        h('b', null, a.name), h('span', { class: 'muted' }, a.desc)))),
    h('div', { class: 'callout' }, `Connected to ${info.vendor || 'an LDAP directory'}${info.isAD ? ` (${domain})` : ''}. `,
      info.isAD ? 'People will log in with their AD login name; you can change that under More options in the next step.'
        : 'People will log in with their uid; you can change that under More options in the next step.'));

  const stepWho = () => {
    const app = appInfo[st.app].name;
    const warn = h('div', { class: 'error-text', role: 'alert', hidden: !groupWarning }, 'Add at least one group, or choose \u201ceveryone\u201d. With no group the settings would let everyone in.');
    const groupBox = h('div', { class: 'indent', hidden: st.who !== 'groups' },
      groupPicker(st.groups, () => { if (st.groups.length) warn.hidden = true; changed(); }),
      warn,
      info.isAD ? checkbox(st.nested, (ev) => { st.nested = ev.target.checked; changed(); }, 'Include people in sub-groups') : null);
    const setWho = (who) => () => { st.who = who; groupBox.hidden = who !== 'groups'; if (who !== 'groups') warn.hidden = true; changed();
      for (const c of whoBox.querySelectorAll('.choice')) c.classList.toggle('on', c.querySelector('input').checked); };
    const whoBox = h('div', { class: 'choices', role: 'radiogroup', 'aria-label': 'Who can log in' },
      radio('who', st.who === 'everyone', setWho('everyone'), 'Everyone with an active account', ''),
      radio('who', st.who === 'groups', setWho('groups'), 'Only members of certain groups', 'Recommended for internal tools'));

    const loginBox = h('div', { class: 'choices compact' }, loading());
    sample.then((acct) => {
      const forms = info.isAD
        ? [['sAMAccountName', 'login name', acct.sAMAccountName || 'jdoe'], ['userPrincipalName', 'sign-in address', acct.userPrincipalName || (acct.sAMAccountName || 'jdoe') + '@' + domain], ['mail', 'email address', acct.mail || 'jdoe@company.com']]
        : [['uid', 'login name', acct.uid || 'jdoe'], ['mail', 'email address', acct.mail || 'jdoe@company.com']];
      if (!forms.some(([a]) => a === st.loginAttr)) forms.push([st.loginAttr, 'custom field', st.loginAttr]);
      loginBox.replaceChildren(...forms.map(([attr, label, example]) => h('label', { class: 'check' },
        h('input', { type: 'radio', name: 'login', checked: st.loginAttr === attr, onchange: () => { st.loginAttr = attr; changed(); } }),
        h('span', null, h('code', null, example), ' ', h('span', { class: 'muted' }, label)))));
    });
    const baseSel = h('select', { 'aria-label': 'Look for accounts in', onchange: (ev) => { st.userBase = ev.target.value; changed(); } },
      h('option', { value: '' }, `All of ${domain}`));
    ous.then((list) => {
      for (const dn of list) baseSel.append(h('option', { value: dn, selected: st.userBase.toLowerCase() === dn.toLowerCase() }, `${domain} › ${ouPath(dn)}`));
      if (st.userBase && !list.some((d) => d.toLowerCase() === st.userBase.toLowerCase())) baseSel.append(h('option', { value: st.userBase, selected: true }, st.userBase));
    });

    return h('div', { class: 'step-pane' },
      h('h2', null, `Who can log in to ${app}?`),
      whoBox, groupBox,
      st.app === 'gitea' ? h('div', { class: 'sub-block' },
        h('div', { class: 'sub-title' }, 'Admins ', h('span', { class: 'muted' }, '· optional')),
        groupPicker(st.admins, changed, { placeholder: 'Add an admin group…', tone: 'admin' })) : null,
      h('details', { class: 'more' },
        h('summary', null, 'More options'),
        h('div', { class: 'more-body' },
          h('div', { class: 'field' }, h('span', null, 'What do people type to log in?'), loginBox),
          h('label', { class: 'field' }, h('span', null, 'Look for accounts in'), baseSel),
          info.isAD ? checkbox(st.excludeDisabled, (ev) => { st.excludeDisabled = ev.target.checked; changed(); }, 'Leave out disabled accounts') : null,
          checkbox(st.requireEmail, (ev) => { st.requireEmail = ev.target.checked; changed(); }, 'Only accounts with an email address', st.app === 'generic' ? '' : `(${app} needs one)`),
          h('label', { class: 'field' }, h('span', null, 'Kind of account'),
            h('select', { onchange: (ev) => { st.accounts = ev.target.value; changed(); } },
              Object.entries(accountClasses).map(([k, a]) => h('option', { value: k, selected: st.accounts === k }, a.label)))))));
  };

  const stepTest = () => {
    const out = h('div', { 'aria-live': 'polite' });
    const who = h('input', { name: 'test-username', placeholder: 'Login name, e.g. ' + (lastPeople[0] ? rdnValue(lastPeople[0].dn).toLowerCase() : 'jdoe'), autocomplete: 'off', 'aria-label': 'Login name to test' });
    const pw = h('input', { name: 'test-password', type: 'password', autocomplete: 'new-password', placeholder: 'Password', 'aria-label': 'Password', hidden: true });
    const pwHint = h('p', { class: 'muted hint', hidden: true }, 'Used for one sign-in and never saved. A wrong password counts toward AD’s lockout limit.');
    const pwToggle = h('button', { type: 'button', class: 'link-btn', onclick: () => { pw.hidden = pwHint.hidden = false; pwToggle.remove(); pw.focus(); } }, 'Also test the password');
    const run = async (ev) => {
      ev?.preventDefault();
      const name = who.value.trim();
      if (!name) return who.focus();
      const current = claim(out);
      out.replaceChildren(loading(`Testing ${name}…`));
      try {
        const res = await api.checkLogin({ ...checkPayload(st.app, settings()), username: name, password: pw.value });
        if (!current()) return;
        const sum = verdict(res.steps, name, st.app === 'generic' ? 'the app' : appInfo[st.app].name);
        const failed = res.steps.find((s) => s.status === 'fail');
        out.replaceChildren(...nodes(
          h('div', { class: 'summary ' + sum.status }, h('span', { class: 'mark' }, statusMark[sum.status] || '!'), sum.text,
            sum.note ? h('span', { class: 'summary-note' }, sum.note) : null),
          failed ? renderStep(failed, name, { compact: true }) : null,
          h('details', { class: 'all-steps', open: false },
            h('summary', null, 'Step by step'),
            h('div', { class: 'steps' }, res.steps.map((s) => renderStep(s, name, { why: false }))))));
      } catch (err) {
        if (current()) out.replaceChildren(errorBox(err));
      }
    };
    const tries = lastPeople.slice(0, 3).map((e) => {
      const login = e.attributes.find((a) => a.name.toLowerCase() === st.loginAttr.toLowerCase())?.values[0]?.text;
      return login ? h('button', { type: 'button', class: 'pill', onclick: () => { who.value = login; run(); } }, login) : null;
    });
    return h('form', { class: 'step-pane', onsubmit: run },
      h('h2', null, 'Try it with a real person'),
      h('p', { class: 'muted' }, `Replays ${appInfo[st.app].name === 'Other app' ? 'the' : appInfo[st.app].name + '’s'} login with these settings. If it fails, you see exactly which condition stops them.`),
      h('div', { class: 'inline-form' }, who, h('button', { type: 'submit', class: 'primary' }, 'Test')),
      pw, pwHint,
      nodes(tries).length ? h('div', { class: 'tries' }, h('span', { class: 'muted' }, 'Try:'), ...nodes(tries)) : null,
      pwToggle, out,
      h('p', { class: 'muted hint' }, 'Already have settings in an app? ', h('a', { href: '#/test?app=' + st.app }, 'Test them as they are')));
  };

  const stepCopy = () => {
    const rows = settingRows(st.app, settings(), info.baseDN);
    const forest = forestHint(info);
    const all = copyAllText(st.app, rows);
    const copyAll = h('button', { type: 'button', class: 'primary', onclick: async () => {
      try { await navigator.clipboard.writeText(all); copyAll.textContent = 'Copied'; } catch { copyAll.textContent = 'Copy failed'; }
      setTimeout(() => { copyAll.textContent = 'Copy all'; }, 1500);
    } }, 'Copy all');
    return h('div', { class: 'step-pane' },
      h('div', { class: 'row-head' }, h('h2', null, `Paste these into ${appInfo[st.app].name === 'Other app' ? 'your app' : appInfo[st.app].name}`), copyAll),
      h('p', { class: 'muted' }, appInfo[st.app].where),
      forest ? h('div', { class: 'callout warn' }, forest.text) : null,
      h('div', { class: 'settings' }, rows.map((r) => h('div', { class: 'setting-row' },
        h('div', null, h('div', { class: 'setting-name' }, r.plain), h('div', { class: 'setting-orig' }, r.original)),
        r.value ? h('code', null, r.value) : h('span', { class: 'muted' }, 'Leave empty'),
        r.value ? copyButton(r.value) : h('span')))));
  };

  const draw = () => {
    stepper.replaceChildren(...stepLabels.map((label, i) => {
      const n = i + 1;
      const cls = n === st.step ? 'current' : n < st.step ? 'done' : '';
      return h('li', { class: cls }, h('button', { type: 'button', onclick: () => go(n), 'aria-current': n === st.step ? 'step' : null },
        h('span', { class: 'dot' }, n < st.step ? '✓' : String(n)), label));
    }));
    body.replaceChildren([stepApp, stepWho, stepTest, stepCopy][st.step - 1]());
    footer.replaceChildren(...nodes(
      st.step > 1 ? h('button', { type: 'button', onclick: () => go(st.step - 1) }, 'Back') : null,
      h('span', { class: 'spacer' }),
      st.step < 4 ? h('button', { type: 'button', class: 'primary', onclick: () => go(st.step + 1) },
        st.step === 3 ? 'Get the settings' : 'Next') : h('button', { type: 'button', onclick: () => go(1) }, 'Start over')));
  };

  el.replaceChildren(h('div', { class: 'page narrow' },
    h('div', { class: 'page-head' }, h('h1', null, 'Set up LDAP login for an app'),
      h('p', { class: 'muted' }, 'Four steps. Nothing is written to the directory; you copy the result into your app.')),
    stepper,
    h('div', { class: 'wizard' },
      h('section', { class: 'card wizard-main' }, body, footer),
      h('aside', { class: 'card wizard-side', 'aria-label': 'Live preview' }, h('div', { class: 'eyebrow' }, 'Live preview'), preview,
        h('p', { class: 'muted hint' }, 'Updates as you change step 2. Test anyone in step 3 to see why they can or can’t log in.')))));
  go(st.step); // a saved step 3 or 4 still needs a group, if restricted
  refreshPreview();
}
