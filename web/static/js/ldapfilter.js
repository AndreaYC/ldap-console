// A small RFC 4515 LDAP filter parser. Pure: no DOM access, so it runs
// under node --test. Every node keeps the exact text it was parsed from, so
// a part the UI does not understand can be written back unchanged.
//
// Nodes:
//   { op: 'and' | 'or', children, src }
//   { op: 'not', child, src }
//   { op: 'item', attr, type, value, rule, dn, src }
//     type: 'eq' | 'ge' | 'le' | 'approx' | 'present' | 'sub' | 'ext'
//     value: still escaped as in the filter; parts for 'sub' (see below)
//     sub: parts = { initial, any: [], final }, each escaped, '' when absent

export class FilterError extends Error {}

export function parse(text) {
  const s = String(text ?? '').trim();
  let i = 0;
  const fail = (msg) => { throw new FilterError(`${msg} at position ${i + 1}`); };

  const node = () => {
    const start = i;
    if (s[i] !== '(') fail('expected "("');
    i++;
    let n;
    const c = s[i];
    if (c === '&' || c === '|') {
      i++;
      const children = [];
      while (s[i] === '(') children.push(node());
      if (!children.length) fail('expected a condition');
      n = { op: c === '&' ? 'and' : 'or', children };
    } else if (c === '!') {
      i++;
      n = { op: 'not', child: node() };
    } else {
      n = item();
    }
    if (s[i] !== ')') fail('expected ")"');
    i++;
    n.src = s.slice(start, i);
    return n;
  };

  // item reads "attr[:dn][:rule]op value" up to the closing ")".
  const item = () => {
    const m = /^([A-Za-z0-9][A-Za-z0-9.;-]*)?((?::dn)?)((?::[A-Za-z0-9.-]+)?)(:=|>=|<=|~=|=)/i.exec(s.slice(i));
    if (!m || (!m[1] && !m[3])) fail('expected an attribute');
    i += m[0].length;
    const start = i;
    while (i < s.length && s[i] !== ')') {
      if (s[i] === '(') fail('unescaped "(" in a value');
      i += s[i] === '\\' ? 3 : 1;
    }
    const value = s.slice(start, i);
    const [, attr = '', dn, rule, op] = m;
    if (op === ':=') return { op: 'item', type: 'ext', attr, dn: !!dn, rule: rule.slice(1), value };
    if (op === '>=') return { op: 'item', type: 'ge', attr, value };
    if (op === '<=') return { op: 'item', type: 'le', attr, value };
    if (op === '~=') return { op: 'item', type: 'approx', attr, value };
    if (value === '*') return { op: 'item', type: 'present', attr, value };
    if (!value.includes('*')) return { op: 'item', type: 'eq', attr, value };
    const pieces = value.split('*');
    return { op: 'item', type: 'sub', attr, value,
      parts: { initial: pieces[0], any: pieces.slice(1, -1).filter(Boolean), final: pieces[pieces.length - 1] } };
  };

  if (!s) throw new FilterError('the filter is empty');
  // A bare "attr=value" is accepted the way most tools accept it.
  const wrapped = s.startsWith('(');
  const root = wrapped ? node() : (() => { const n = item(); n.src = `(${s})`; return n; })();
  if (wrapped && i !== s.length) fail('unexpected text after the filter');
  return root;
}

// serialize writes a node back as filter text. Parsed nodes keep their
// source; built nodes are rendered.
export function serialize(n) {
  if (n.src) return n.src;
  switch (n.op) {
    case 'and': return `(&${n.children.map(serialize).join('')})`;
    case 'or': return `(|${n.children.map(serialize).join('')})`;
    case 'not': return `(!${serialize(n.child)})`;
  }
  const ops = { eq: '=', ge: '>=', le: '<=', approx: '~=', present: '=', sub: '=' };
  if (n.type === 'ext') return `(${n.attr}${n.dn ? ':dn' : ''}${n.rule ? ':' + n.rule : ''}:=${n.value})`;
  return `(${n.attr}${ops[n.type]}${n.value})`;
}

// escapeValue escapes an assertion value per RFC 4515: \ * ( ) and NUL.
export function escapeValue(v) {
  return String(v).replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

const utf8 = new TextDecoder();

// unescapeValue decodes \XX escapes (hex only, as RFC 4515 has no other
// form), reading consecutive pairs as one UTF-8 sequence.
export function unescapeValue(v) {
  if (!v.includes('\\')) return v;
  const enc = new TextEncoder();
  const bytes = [];
  for (let i = 0; i < v.length; i++) {
    if (v[i] === '\\' && /^[0-9a-fA-F]{2}$/.test(v.slice(i + 1, i + 3))) {
      bytes.push(parseInt(v.slice(i + 1, i + 3), 16));
      i += 2;
      continue;
    }
    const cp = v.codePointAt(i);
    if (cp > 0xffff) i++;
    bytes.push(...enc.encode(String.fromCodePoint(cp)));
  }
  return utf8.decode(new Uint8Array(bytes));
}
