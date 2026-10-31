import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseNames, pivotGroups, cellLabel, listRows } from '../static/js/pivot.js';

test('parseNames splits on lines, commas, semicolons and tabs, and dedupes', () => {
  assert.deepEqual(parseNames('alice, bob;carol\n\n  Alice \nCORP\\dave\te@x.local'),
    ['alice', 'bob', 'carol', 'CORP\\dave', 'e@x.local']);
});

test('parseNames keeps a DN line whole', () => {
  assert.deepEqual(parseNames('CN=Smith\\, John,OU=Users,DC=corp,DC=local\nbob'),
    ['CN=Smith\\, John,OU=Users,DC=corp,DC=local', 'bob']);
});

const g = (name, extra = {}) => ({ dn: `CN=${name},OU=Groups,DC=x`, name, kind: 'group', direct: true, ...extra });

test('pivotGroups lines up found people and sorts by how many share a group', () => {
  const { people, rows } = pivotGroups([
    { query: 'a', status: 'found', matches: [{ dn: 'CN=A,DC=x', name: 'A' }], groups: [g('Eng'), g('All', { direct: false, via: ['CN=Eng,OU=Groups,DC=x'] })] },
    { query: 'nobody', status: 'notFound' },
    { query: 'b', status: 'found', matches: [{ dn: 'CN=B,DC=x', name: 'B' }], groups: [g('all'.replace('a', 'A')), g('Ops'), g('Users', { primary: true })] },
  ]);
  assert.equal(people.length, 2);
  assert.deepEqual(rows.map((r) => [r.group.name, r.count, r.direct]), [['All', 2, 1], ['Eng', 1, 1], ['Ops', 1, 1], ['Users', 1, 1]]);
  assert.deepEqual(rows[0].cells.map(cellLabel), ['nested', 'direct']);
  assert.deepEqual(rows[1].cells.map(cellLabel), ['direct', '']);
  assert.equal(cellLabel(rows[3].cells[1]), 'primary');
});

test('pivotGroups gives two names for the same account one column', () => {
  const alice = { dn: 'CN=Alice,DC=x', name: 'Alice' };
  const { people, rows } = pivotGroups([
    { query: 'alice', status: 'found', matches: [alice], groups: [g('Eng')] },
    { query: 'alice@x', status: 'found', matches: [{ ...alice, dn: 'cn=alice,dc=x' }], groups: [g('Eng')] },
  ]);
  assert.deepEqual(people.map((p) => p.query), ['alice']);
  assert.equal(rows[0].count, 1);
});

test('pivotGroups matches group DNs case-insensitively', () => {
  const { rows } = pivotGroups([
    { status: 'found', matches: [{ dn: 'CN=A,DC=x' }], groups: [g('Eng')] },
    { status: 'found', matches: [{ dn: 'CN=B,DC=x' }], groups: [{ ...g('Eng'), dn: 'cn=eng,ou=groups,dc=x' }] },
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].count, 2);
});

test('listRows keeps accounts without groups and unresolved names', () => {
  const rows = listRows([
    { query: 'a', status: 'found', matches: [{ dn: 'CN=A,DC=x', name: 'A' }] }, // groups omitted by the server
    { query: 'b', status: 'found', matches: [{ dn: 'CN=B,DC=x', name: 'B' }], groups: [g('All', { direct: false, via: ['CN=Eng,OU=Groups,DC=x'] })] },
    { query: 'zz', status: 'notFound' },
  ]);
  assert.deepEqual(rows, [
    ['a', 'found', 'A', 'CN=A,DC=x', '', '', '', ''],
    ['b', 'found', 'B', 'CN=B,DC=x', 'All', 'nested', 'Eng', 'CN=All,OU=Groups,DC=x'],
    ['zz', 'notFound', '', '', '', '', '', ''],
  ]);
});
