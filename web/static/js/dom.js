import { toCSV } from './csv.js';
import { terms } from './terms.js';
export { termText } from './terms.js';
export { claim } from './claim.js';
export { splitDN, rdnValue } from './format.js';

// Tiny DOM helpers. All text goes through textContent / text nodes, never
// innerHTML: directory values are untrusted.

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

// term renders a label as plain English with the original term after it in
// code style: "Where to search (Base DN)". plain overrides the glossary's
// wording where the context needs a different phrase.
export function term(key, plain) {
  const [p, original] = terms[key];
  return plainTerm(plain ?? p, original);
}

// plainTerm is term for a pairing outside the glossary, such as an
// application's own setting name.
export function plainTerm(plain, original) {
  return [plain, ' ', h('span', { class: 'term' }, '(', h('code', null, original), ')')];
}

// membershipTag labels how an account is in a group. Tags stay short in
// dense tables; membershipLegend carries the original terms once.
export function membershipTag(m, via) {
  if (m.primary) return h('span', { class: 'tag primary', title: 'Default group (primary group): AD’s primaryGroupID, never listed in memberOf' }, 'default group');
  if (m.direct) return h('span', { class: 'tag direct', title: 'Directly (direct): the group lists this member itself' }, 'direct');
  return h('span', { class: 'tag', title: 'Through a sub-group (nested)' + (via?.length ? ': ' + via.join(' › ') : '') }, 'via sub-group');
}

export function membershipLegend() {
  return h('div', { class: 'legend muted' },
    h('span', { class: 'tag direct' }, 'direct'), ' ', term('direct', 'the group lists them itself'), ' · ',
    h('span', { class: 'tag' }, 'via sub-group'), ' ', term('nested', 'they are in a group inside it'), ' · ',
    h('span', { class: 'tag primary' }, 'default group'), ' ', term('primary', 'AD’s default group, e.g. Domain Users, which memberOf never lists'));
}

const kindLabels = {
  container: 'OU', user: 'U', group: 'G', computer: 'PC',
  contact: 'CT', foreignSecurityPrincipal: 'FSP', other: '•', unknown: '?',
};

// nodes drops null/false so optional pieces can be passed to append/replaceChildren.
export function nodes(...items) {
  return items.flat(Infinity).filter((c) => c != null && c !== false);
}

// kindBadge labels an entry's kind; pass dn to tell a domain from an OU.
export function kindBadge(kind, dn) {
  if (kind === 'container' && /^dc=/i.test(dn || '')) return h('span', { class: 'kind container', title: 'domain' }, 'DC');
  return h('span', { class: `kind ${kind}`, title: kind }, kindLabels[kind] || '•');
}

export function errorBox(err) {
  return h('div', { class: 'error' }, err.message || String(err));
}

export function loading(text = 'Loading…') {
  return h('div', { class: 'empty' }, text);
}

// entryLink navigates to an entry in the Browse view.
export function entryLink(dn, text) {
  return h('a', { href: '#/browse?dn=' + encodeURIComponent(dn), title: dn }, text ?? dn);
}

export function copyButton(text) {
  const icon = '⧉';
  const b = h('button', {
    type: 'button', class: 'icon-btn', title: 'Copy', 'aria-label': 'Copy',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        b.textContent = '✓';
      } catch {
        b.textContent = '✗';
        b.title = 'Copy failed';
      }
      setTimeout(() => { b.textContent = icon; b.title = 'Copy'; }, 1200);
    },
  }, icon);
  return b;
}

export function downloadCSV(filename, header, rows) {
  const text = toCSV(header, rows);
  const url = URL.createObjectURL(new Blob(['﻿' + text], { type: 'text/csv;charset=utf-8' }));
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
