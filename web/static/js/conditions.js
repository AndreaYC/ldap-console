// Directory search as plain conditions (the filter chips) and back. Pure:
// no DOM access, so it runs under node --test.
//
// A search is { type, q, match, conds }:
//   type  '' (anything) | 'people' | 'groups' | 'computers'
//   q     the search box text, matched against names, logins and emails
//   match 'all' | 'any' — how conds combine
//   conds the chips, see `kinds` below
// The filter string is the source of truth; fromFilter and toFilter convert.
import { parse, serialize, escapeValue, unescapeValue } from './ldapfilter.js';
import { rdnValue } from './format.js';

const IN_CHAIN = '1.2.840.113556.1.4.1941';
const BIT_AND = '1.2.840.113556.1.4.803';

export const types = {
  people: { label: 'People', ad: ['(objectCategory=person)', '(objectClass=user)'], ldap: ['(|(objectClass=inetOrgPerson)(objectClass=posixAccount))'] },
  groups: { label: 'Groups', ad: ['(objectClass=group)'], ldap: ['(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))'] },
  computers: { label: 'Computers', ad: ['(objectClass=computer)'], ldap: ['(objectClass=computer)'] },
};

// nameAttrs are what the search box matches, as the quick find does.
export const nameAttrs = ['cn', 'displayName', 'sAMAccountName', 'uid', 'mail', 'userPrincipalName'];

// FILETIME (100 ns since 1601) for lastLogonTimestamp, in BigInt: the
// values exceed 2^53.
const EPOCH_GAP_MS = 11644473600000n;
const DAY_MS = 86400000n;
function filetimeDaysAgo(days, now) {
  return ((BigInt(now) - BigInt(days) * DAY_MS + EPOCH_GAP_MS) * 10000n).toString();
}
function daysAgoOfFiletime(ft, now) {
  const ms = BigInt(ft) / 10000n - EPOCH_GAP_MS;
  return Number((BigInt(now) - ms + DAY_MS / 2n) / DAY_MS);
}

const fieldOps = {
  is: 'is', not: 'is not', contains: 'contains', starts: 'starts with', ends: 'ends with',
  has: 'has a value', missing: 'has no value', gte: 'is at least', lte: 'is at most',
};
export const fieldOpLabels = fieldOps;

// kinds: each chip's clause, its words for the chip, and whether it is AD-only.
export const kinds = {
  group: {
    menu: 'In group…', hint: 'Directly or through sub-groups',
    clause: (c) => `(memberOf${c.nested ? ':' + IN_CHAIN + ':' : ''}=${escapeValue(c.dn)})`,
    words: (c) => ['In group', rdnValue(c.dn) + (c.nested ? '' : ' (directly)')],
  },
  disabled: {
    menu: 'Account is disabled', hint: 'Can’t sign in', ad: true,
    clause: (c) => c.not ? `(!(userAccountControl:${BIT_AND}:=2))` : `(userAccountControl:${BIT_AND}:=2)`,
    words: (c) => ['Account', c.not ? 'not disabled' : 'disabled'],
  },
  locked: {
    menu: 'Has been locked out', hint: 'Too many wrong passwords', ad: true,
    clause: () => '(lockoutTime>=1)',
    words: () => ['Account', 'locked out'],
  },
  neverExpires: {
    menu: 'Password never expires', hint: 'Often service accounts', ad: true,
    clause: () => `(userAccountControl:${BIT_AND}:=65536)`,
    words: () => ['Password', 'never expires'],
  },
  idle: {
    menu: 'Not logged in for…', hint: 'Stale accounts; AD updates this every 1–2 weeks', ad: true,
    clause: (c, now) => `(lastLogonTimestamp<=${filetimeDaysAgo(c.days, now)})`,
    words: (c) => ['Not logged in for', `${c.days}+ days`],
  },
  neverLoggedIn: {
    menu: 'Never logged in', hint: 'Accounts nobody has used', ad: true,
    clause: () => '(!(lastLogonTimestamp=*))',
    words: () => ['Never logged in', ''],
  },
  empty: {
    menu: 'Group has no members', hint: 'Candidates for clean-up',
    // Groups list members in member (AD, groupOfNames), uniqueMember or
    // memberUid (posixGroup); empty means none of them.
    clause: () => '(&(!(member=*))(!(uniqueMember=*))(!(memberUid=*)))',
    words: () => ['Group', 'has no members'],
  },
  admin: {
    menu: 'Protected admin accounts', hint: 'adminCount is set', ad: true,
    clause: () => '(adminCount=1)',
    words: () => ['Admin', 'protected account'],
  },
  field: {
    menu: 'Any field…', hint: 'Pick a field and a value',
    clause: (c) => {
      const v = escapeValue(c.value ?? '');
      return {
        is: `(${c.attr}=${v})`, not: `(!(${c.attr}=${v}))`, contains: `(${c.attr}=*${v}*)`, starts: `(${c.attr}=${v}*)`,
        ends: `(${c.attr}=*${v})`, has: `(${c.attr}=*)`, missing: `(!(${c.attr}=*))`, gte: `(${c.attr}>=${v})`, lte: `(${c.attr}<=${v})`,
      }[c.op];
    },
    words: (c) => [c.attr, fieldOps[c.op] + (c.op === 'has' || c.op === 'missing' ? '' : ' ' + c.value)],
  },
  raw: {
    clause: (c) => c.src,
    words: (c) => ['Other condition', c.src],
  },
};

export function chipWords(c) {
  return kinds[c.k].words(c);
}

function clauseOf(c, now) {
  return kinds[c.k].clause(c, now);
}

function nameQuery(q) {
  const v = escapeValue(q);
  return '(|' + nameAttrs.map((a) => `(${a}=*${v}*)`).join('') + ')';
}

// toFilter writes a search as one LDAP filter.
export function toFilter({ type = '', q = '', match = 'all', conds = [] }, isAD, now = Date.now()) {
  const clauses = [...(type ? types[type][isAD ? 'ad' : 'ldap'] : [])];
  if (q.trim()) clauses.push(nameQuery(q.trim()));
  const cs = conds.map((c) => clauseOf(c, now));
  if (match === 'any' && cs.length > 1) clauses.push('(|' + cs.join('') + ')');
  else clauses.push(...cs);
  if (!clauses.length) return '(objectClass=*)';
  if (clauses.length === 1) return clauses[0];
  return '(&' + clauses.join('') + ')';
}

const norm = (s) => s.replace(/\s+/g, '').toLowerCase();

// asQuery recognises the search box's OR of substring tests.
// Only the exact attribute set counts: a narrower OR pasted by hand must
// stay as written, not widen to every name attribute.
function asQuery(n) {
  if (n.op !== 'or' || n.children.length !== nameAttrs.length) return null;
  const want = new Set(nameAttrs.map((a) => a.toLowerCase()));
  let value = null;
  for (const c of n.children) {
    if (c.op !== 'item' || c.type !== 'sub' || c.parts.initial || c.parts.final || c.parts.any.length !== 1) return null;
    if (!want.delete(c.attr.toLowerCase())) return null;
    if (value !== null && value !== c.parts.any[0]) return null;
    value = c.parts.any[0];
  }
  return unescapeValue(value);
}

const memberAttrs = ['member', 'uniquemember', 'memberuid'];

// isEmptyGroup recognises the empty-group clause: no member attribute at all.
function isEmptyGroup(n) {
  if (n.op !== 'and' || n.children.length !== memberAttrs.length) return false;
  const seen = new Set();
  for (const c of n.children) {
    if (c.op !== 'not' || c.child.op !== 'item' || c.child.type !== 'present') return false;
    seen.add(c.child.attr.toLowerCase());
  }
  return memberAttrs.every((a) => seen.has(a));
}

const isItem = (n, type, attr) => n.op === 'item' && n.type === type && n.attr.toLowerCase() === attr.toLowerCase();

// asCond recognises one chip, or returns a raw one keeping the text as given.
function asCond(n, now) {
  if (n.op === 'item') {
    if (n.type === 'eq' && n.attr.toLowerCase() === 'memberof') return { k: 'group', dn: unescapeValue(n.value), nested: false };
    if (n.type === 'ext' && n.attr.toLowerCase() === 'memberof' && n.rule === IN_CHAIN && !n.dn) return { k: 'group', dn: unescapeValue(n.value), nested: true };
    if (n.type === 'ext' && n.attr.toLowerCase() === 'useraccountcontrol' && n.rule === BIT_AND && n.value === '2') return { k: 'disabled', not: false };
    if (n.type === 'ext' && n.attr.toLowerCase() === 'useraccountcontrol' && n.rule === BIT_AND && n.value === '65536') return { k: 'neverExpires' };
    if (isItem(n, 'ge', 'lockoutTime') && n.value === '1') return { k: 'locked' };
    if (isItem(n, 'le', 'lastLogonTimestamp') && /^\d+$/.test(n.value)) return { k: 'idle', days: daysAgoOfFiletime(n.value, now) };
    if (isItem(n, 'eq', 'adminCount') && n.value === '1') return { k: 'admin' };
    if (n.type !== 'ext' && n.type !== 'approx' && /^[A-Za-z][A-Za-z0-9-]*$/.test(n.attr)) {
      const v = (x) => unescapeValue(x);
      if (n.type === 'eq') return { k: 'field', attr: n.attr, op: 'is', value: v(n.value) };
      if (n.type === 'present') return { k: 'field', attr: n.attr, op: 'has', value: '' };
      if (n.type === 'ge') return { k: 'field', attr: n.attr, op: 'gte', value: v(n.value) };
      if (n.type === 'le') return { k: 'field', attr: n.attr, op: 'lte', value: v(n.value) };
      const { initial, any, final } = n.parts;
      if (!initial && !final && any.length === 1) return { k: 'field', attr: n.attr, op: 'contains', value: v(any[0]) };
      if (initial && !final && !any.length) return { k: 'field', attr: n.attr, op: 'starts', value: v(initial) };
      if (!initial && final && !any.length) return { k: 'field', attr: n.attr, op: 'ends', value: v(final) };
    }
  }
  if (isEmptyGroup(n)) return { k: 'empty' };
  if (n.op === 'not') {
    const c = n.child;
    if (c.op === 'item' && c.type === 'ext' && c.attr.toLowerCase() === 'useraccountcontrol' && c.rule === BIT_AND && c.value === '2') return { k: 'disabled', not: true };
    if (isItem(c, 'present', 'lastLogonTimestamp')) return { k: 'neverLoggedIn' };
    if (c.op === 'item' && c.type === 'present' && /^[A-Za-z][A-Za-z0-9-]*$/.test(c.attr)) return { k: 'field', attr: c.attr, op: 'missing', value: '' };
    if (c.op === 'item' && c.type === 'eq' && /^[A-Za-z][A-Za-z0-9-]*$/.test(c.attr)) return { k: 'field', attr: c.attr, op: 'not', value: unescapeValue(c.value) };
  }
  return { k: 'raw', src: serialize(n) };
}

// fromFilter reads a filter back into a search. Throws FilterError when the
// text is not a filter. Parts it does not recognise become raw chips that
// keep their exact text.
export function fromFilter(text, now = Date.now()) {
  const root = parse(text);
  if (norm(root.src) === '(objectclass=*)') return { type: '', q: '', match: 'all', conds: [] };
  let rest = root.op === 'and' ? [...root.children] : [root];
  let type = '';
  for (const [id, t] of Object.entries(types)) {
    for (const variant of [t.ad, t.ldap]) {
      const want = variant.map(norm);
      if (want.every((w) => rest.some((n) => norm(n.src) === w)) && rest.length >= want.length) {
        // computers are users too on AD: prefer the longest match
        if (!type || want.length > types[type].ad.length) {
          type = id;
          rest = rest.filter((n) => !want.includes(norm(n.src)));
        }
        break;
      }
    }
    if (type) break;
  }
  let q = '';
  const qi = rest.findIndex((n) => asQuery(n) !== null);
  if (qi >= 0) {
    q = asQuery(rest[qi]);
    rest.splice(qi, 1);
  }
  let match = 'all';
  if (rest.length === 1 && rest[0].op === 'or') {
    match = 'any';
    rest = rest[0].children;
  }
  return { type, q, match, conds: rest.map((n) => asCond(n, now)) };
}

// presets are the sidebar's saved views.
export const presets = [
  { label: 'Disabled accounts', search: { type: 'people', conds: [{ k: 'disabled', not: false }] }, ad: true },
  { label: 'Locked out', search: { type: 'people', conds: [{ k: 'locked' }] }, ad: true },
  { label: 'Password never expires', search: { type: 'people', conds: [{ k: 'neverExpires' }] }, ad: true },
  { label: 'Not logged in for 90 days', search: { type: 'people', conds: [{ k: 'idle', days: 90 }, { k: 'disabled', not: true }] }, ad: true },
  { label: 'Empty groups', search: { type: 'groups', conds: [{ k: 'empty' }] } },
  { label: 'Protected admins', search: { type: '', conds: [{ k: 'admin' }] }, ad: true },
  { label: 'All groups', search: { type: 'groups', conds: [] } },
  { label: 'All computers', search: { type: 'computers', conds: [] }, ad: true },
];
