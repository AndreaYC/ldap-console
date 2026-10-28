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

const kindLabels = {
  container: 'OU', user: 'U', group: 'G', computer: 'PC',
  contact: 'CT', foreignSecurityPrincipal: 'FSP', other: '•', unknown: '?',
};

// nodes drops null/false so optional pieces can be passed to append/replaceChildren.
export function nodes(...items) {
  return items.flat(Infinity).filter((c) => c != null && c !== false);
}

export function kindBadge(kind) {
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

// rdnValue returns the value of the first RDN ("CN=Alice,OU=x" -> "Alice").
export function rdnValue(dn) {
  const first = splitDN(dn)[0] || dn;
  const i = first.indexOf('=');
  return (i < 0 ? first : first.slice(i + 1)).replace(/\\(.)/g, '$1');
}

// splitDN splits on unescaped commas.
export function splitDN(dn) {
  const out = [];
  let cur = '';
  for (let i = 0; i < dn.length; i++) {
    const c = dn[i];
    if (c === '\\' && i + 1 < dn.length) { cur += c + dn[++i]; continue; }
    if (c === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function copyButton(text) {
  const b = h('button', {
    title: 'Copy',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        b.textContent = 'Copied';
      } catch {
        b.textContent = 'Copy failed';
      }
      setTimeout(() => { b.textContent = 'Copy'; }, 1200);
    },
  }, 'Copy');
  return b;
}

export function downloadCSV(filename, header, rows) {
  const esc = (v) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? '"' + s.replaceAll('"', '""') + '"' : s;
  };
  const text = [header, ...rows].map((r) => r.map(esc).join(',')).join('\n');
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
