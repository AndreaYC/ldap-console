import { api } from './api.js';
import { h, nodes, kindBadge, entryLink, errorBox, loading, rdnValue, claim, term } from './dom.js';
import { blockers, valuesFor } from './explaintree.js';

const maxValues = 8;

function valueText(v) {
  if (v.dn) return rdnValue(v.text);
  return v.note ? `${v.text} (${v.note})` : v.text;
}

// accountValues shows what the account actually holds for a test's attribute.
function accountValues(node, values, name) {
  if (node.op !== 'test' || !node.attr) return null;
  const vals = valuesFor(values, node.attr);
  if (!vals.length) {
    return h('div', { class: 'explain-values muted' }, `${name} has no ${node.attr} value, or the sign-in account can’t read it`);
  }
  const shown = vals.slice(0, maxValues).map(valueText).join(' · ');
  const more = vals.length > maxValues ? ` · +${vals.length - maxValues} more` : '';
  return h('div', { class: 'explain-values muted' }, `${name}’s ${node.attr}: `, h('span', { class: 'mono' }, shown + more));
}

function treeNode(node, values, name) {
  return h('li', { class: 'explain-node ' + (node.match ? 'ok' : 'fail') },
    h('div', { class: 'explain-row' },
      h('span', { class: 'mark' }, node.match ? '✓' : '✗'),
      h('span', null, node.say),
      node.op === 'test' ? h('code', { class: 'explain-filter' }, node.filter) : null),
    accountValues(node, values, name),
    node.hint ? h('div', { class: 'explain-hint' }, '\u2192 ', node.hint) : null,
    node.children?.length ? h('ul', null, node.children.map((c) => treeNode(c, values, name))) : null);
}

// renderExplanation shows whether the account matches and, if not, the
// parts that stop it, above the full tree of the filter.
function renderExplanation(res, recheck) {
  if (res.status === 'notFound') {
    return h('div', { class: 'summary warn' }, h('span', { class: 'mark' }, '!'),
      `No account has the login name, email, name or full path (DN) ${res.query}`);
  }
  if (res.status === 'ambiguous') {
    return h('div', null,
      h('div', { class: 'summary warn' }, h('span', { class: 'mark' }, '!'), `${res.matches.length} accounts are called ${res.query}; pick one`),
      h('ul', { class: 'step-items' }, res.matches.map((o) => h('li', null, kindBadge(o.kind), entryLink(o.dn, o.name),
        h('span', { class: 'muted mono' }, o.dn), h('button', { type: 'button', onclick: () => recheck(o.dn) }, 'Check this one')))));
  }
  const who = res.matches[0];
  const name = who.name;
  const reasons = blockers(res.root);
  const head = res.match
    ? h('div', { class: 'summary ok' }, h('span', { class: 'mark' }, '✓'), `${name} matches every condition`)
    : h('div', { class: 'summary fail' }, h('span', { class: 'mark' }, '✗'), `${name} does not match`);
  return h('div', { class: 'explain' }, ...nodes(
    head,
    h('div', { class: 'muted explain-who' }, kindBadge(who.kind, who.dn), ' ', entryLink(who.dn, who.dn),
      who.disabled ? h('span', { class: 'tag disabled', title: 'Disabled (ACCOUNTDISABLE)' }, 'disabled') : null),
    res.match ? null : h('div', { class: 'explain-reasons' }, h('b', null, 'Why: '),
      h('ul', null, ...nodes(
        res.inBase ? null : h('li', null, `${name} is outside `, term('base', 'where to look'), ': ', h('span', { class: 'mono' }, res.base)),
        reasons.map((r) => h('li', null, r.say, r.hint ? h('div', { class: 'explain-hint' }, '\u2192 ', r.hint) : null))))),
    h('details', { class: 'explain-tree', open: !res.match },
      h('summary', null, 'Every condition, checked for ', name),
      h('ul', null, treeNode(res.root, res.values, name)),
      h('div', { class: 'muted hint' }, 'Conditions checked (', h('code', null, 'LDAP filter'), '): ', h('code', null, res.filter)))));
}

// runExplain checks who against filter and renders the answer into el.
export async function runExplain(el, { who, filter, base }) {
  const current = claim(el);
  if (!who) return el.replaceChildren(errorBox(new Error('Enter a login name, email or name.')));
  if (!filter) return el.replaceChildren(errorBox(new Error('There are no conditions to check yet.')));
  el.replaceChildren(loading(`Checking ${who}…`));
  try {
    const res = await api.explain({ who, filter, base });
    if (current()) el.replaceChildren(renderExplanation(res, (dn) => runExplain(el, { who: dn, filter, base })));
  } catch (err) {
    if (current()) el.replaceChildren(errorBox(err));
  }
}

// explainPanel asks for a person and checks them against the filter that
// get() returns at that moment: { filter, base }.
export function explainPanel(get, { label = 'Check a person', placeholder = 'login name, email or name' } = {}) {
  const who = h('input', { name: 'explain-who', placeholder, autocomplete: 'off', 'aria-label': 'Person to check' });
  const out = h('div', { 'aria-live': 'polite' });
  const go = (ev) => { ev?.preventDefault(); runExplain(out, { who: who.value.trim(), ...get() }); };
  who.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') go(ev); });
  return h('div', { class: 'explain-panel' },
    h('div', { class: 'toolbar' }, h('b', null, label), who, h('button', { type: 'button', onclick: go }, 'Why (not)?')),
    out);
}
