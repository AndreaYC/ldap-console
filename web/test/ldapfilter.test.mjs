import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse, serialize, escapeValue, unescapeValue, FilterError } from '../static/js/ldapfilter.js';
import { buildSettings, defaultOptions } from '../static/js/filters.js';

const samples = [
  '(&(objectCategory=person)(objectClass=user))',
  '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))',
  '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))',
  '(&(objectClass=group)(!(member=*)))',
  '(objectClass=computer)',
  '(memberOf=CN=Ops \\28EU\\29,OU=Groups,DC=corp,DC=local)',
  '(cn=*a*b*)', '(cn=a*)', '(cn=*z)', '(cn~=jon)', '(lastLogonTimestamp<=133000000000000000)',
  '(cn:dn:2.5.13.5:=x)', '(:1.2.3:=x)', '(cn=x\\2ay)',
];

test('every sample round-trips unchanged', () => {
  for (const f of samples) assert.equal(serialize(parse(f)), f, f);
});

test('the filters the builder writes round-trip', () => {
  const s = buildSettings({ ...defaultOptions(true), groups: ['CN=R\\, D (x),OU=G,DC=c'], adminGroups: ['CN=A,DC=c'] });
  for (const f of [s.generic.userFilter, s.generic.groupFilter, s.gitea.userFilter, s.gitea.adminFilter, s.preview]) {
    assert.equal(serialize(parse(f)), f, f);
  }
});

test('items are typed, with values still escaped', () => {
  const n = parse('(&(mail=*)(cn=*a*b*)(memberOf:1.2.840.113556.1.4.1941:=CN=X\\28y\\29)(!(x>=3)))');
  assert.equal(n.op, 'and');
  const [present, sub, ext, not] = n.children;
  assert.deepEqual([present.type, present.attr], ['present', 'mail']);
  assert.deepEqual(sub.parts, { initial: '', any: ['a', 'b'], final: '' });
  assert.deepEqual([ext.type, ext.attr, ext.rule, ext.value], ['ext', 'memberOf', '1.2.840.113556.1.4.1941', 'CN=X\\28y\\29']);
  assert.equal(not.op, 'not');
  assert.deepEqual([not.child.type, not.child.value], ['ge', '3']);
});

test('a bare attr=value is accepted', () => {
  assert.equal(serialize(parse('cn=alice')), '(cn=alice)');
});

test('malformed filters throw a FilterError', () => {
  for (const f of ['', '(cn=a', '(&)', '(cn=a)(cn=b)', '((cn=a))', '(cn=a(b)', '(=a)']) {
    assert.throws(() => parse(f), FilterError, f);
  }
});

test('values escape and unescape per RFC 4515', () => {
  assert.equal(escapeValue('a*(b)\\'), 'a\\2a\\28b\\29\\5c');
  assert.equal(unescapeValue('J\\c3\\bcrgen \\28x\\29'), 'Jürgen (x)');
  assert.equal(unescapeValue(escapeValue('R, D (*)')), 'R, D (*)');
});
