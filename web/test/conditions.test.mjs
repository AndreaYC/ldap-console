import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toFilter, fromFilter, chipWords, presets } from '../static/js/conditions.js';

const now = Date.UTC(2026, 10, 2);
const eng = 'CN=Engineering (EU),OU=Groups,DC=corp,DC=local';
const norm = (s) => ({ type: '', q: '', match: 'all', conds: [], ...s });

const searches = [
  { type: 'people', conds: [{ k: 'group', dn: eng, nested: true }, { k: 'disabled', not: true }] },
  { type: 'people', q: 'chen', conds: [{ k: 'idle', days: 90 }] },
  { type: 'groups', conds: [{ k: 'empty' }] },
  { type: 'computers', conds: [] },
  { type: '', conds: [{ k: 'admin' }] },
  { type: 'people', match: 'any', conds: [{ k: 'locked' }, { k: 'neverExpires' }, { k: 'neverLoggedIn' }] },
  { type: '', conds: [{ k: 'group', dn: eng, nested: false }, { k: 'disabled', not: false }] },
  { type: 'people', conds: [
    { k: 'field', attr: 'department', op: 'is', value: 'R&D (x)*' }, { k: 'field', attr: 'title', op: 'contains', value: 'eng' },
    { k: 'field', attr: 'mail', op: 'ends', value: '@corp.local' }, { k: 'field', attr: 'cn', op: 'starts', value: 'a' },
    { k: 'field', attr: 'manager', op: 'has', value: '' }, { k: 'field', attr: 'telephoneNumber', op: 'missing', value: '' },
    { k: 'field', attr: 'l', op: 'not', value: 'Taipei' }, { k: 'field', attr: 'pwdLastSet', op: 'gte', value: '1' },
  ] },
];

test('every search survives filter text and back, on AD and elsewhere', () => {
  for (const isAD of [true, false]) {
    for (const s of searches) {
      if (!isAD && s.type === 'computers') continue;
      assert.deepEqual(fromFilter(toFilter(s, isAD, now), now), norm(s), toFilter(s, isAD, now));
    }
  }
});

test('the presets round-trip too', () => {
  for (const p of presets) assert.deepEqual(fromFilter(toFilter(p.search, true, now), now), norm(p.search), p.label);
});

test('an empty search is every entry', () => {
  assert.equal(toFilter({}, true, now), '(objectClass=*)');
  assert.deepEqual(fromFilter('(objectClass=*)', now), norm({}));
});

test('a pasted filter turns into chips, keeping parts it does not know as written', () => {
  const s = fromFilter('(&(objectCategory=person)(objectClass=user)(memberOf=CN=Ops,DC=x)(|(a=1)(b=2))(cn~=jon))', now);
  assert.equal(s.type, 'people');
  assert.deepEqual(s.conds[0], { k: 'group', dn: 'CN=Ops,DC=x', nested: false });
  assert.deepEqual(s.conds.slice(1), [{ k: 'raw', src: '(|(a=1)(b=2))' }, { k: 'raw', src: '(cn~=jon)' }]);
  assert.equal(toFilter(s, true, now), '(&(objectCategory=person)(objectClass=user)(memberOf=CN=Ops,DC=x)(|(a=1)(b=2))(cn~=jon))');
});

test('a lone OR of conditions is read as "any of these"', () => {
  const s = fromFilter('(|(lockoutTime>=1)(adminCount=1))', now);
  assert.equal(s.match, 'any');
  assert.deepEqual(s.conds.map((c) => c.k), ['locked', 'admin']);
});

test('lastLogonTimestamp converts both ways in whole days', () => {
  const f = toFilter({ conds: [{ k: 'idle', days: 90 }] }, true, now);
  assert.match(f, /^\(lastLogonTimestamp<=\d{18}\)$/);
  assert.equal(fromFilter(f, now + 3 * 86400000).conds[0].days, 93);
});

test('chips read in plain words', () => {
  assert.deepEqual(chipWords({ k: 'group', dn: eng, nested: false }), ['In group', 'Engineering (EU) (directly)']);
  assert.deepEqual(chipWords({ k: 'idle', days: 30 }), ['Not logged in for', '30+ days']);
  assert.deepEqual(chipWords({ k: 'field', attr: 'title', op: 'contains', value: 'eng' }), ['title', 'contains eng']);
});

test('a narrower name OR stays as written instead of widening to every name field', () => {
  for (const f of ['(|(cn=*alice*)(mail=*alice*))', '(&(objectClass=group)(|(cn=*alice*)(mail=*alice*)))']) {
    const s = fromFilter(f, now);
    assert.equal(s.q, '', f);
    assert.equal(toFilter(s, true, now), f);
  }
});

test('the search box OR is recognised in any attribute order', () => {
  const f = '(|(mail=*al*)(uid=*al*)(cn=*al*)(userPrincipalName=*al*)(displayName=*al*)(sAMAccountName=*al*))';
  assert.equal(fromFilter(f, now).q, 'al');
});

test('an empty group has none of member, uniqueMember or memberUid', () => {
  const f = toFilter({ type: 'groups', conds: [{ k: 'empty' }] }, false, now);
  assert.match(f, /\(!\(member=\*\)\)\(!\(uniqueMember=\*\)\)\(!\(memberUid=\*\)\)/);
  assert.deepEqual(fromFilter(f, now).conds, [{ k: 'empty' }]);
  // a hand-written member-only test keeps its meaning
  assert.deepEqual(fromFilter('(&(objectClass=group)(!(member=*)))', now).conds, [{ k: 'field', attr: 'member', op: 'missing', value: '' }]);
});
