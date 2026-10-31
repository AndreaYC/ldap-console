import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blockers, valuesFor } from '../static/js/explaintree.js';

const t = (say, match) => ({ op: 'test', say, match });

test('blockers lists the failed parts of a failed AND, through nested ANDs', () => {
  const root = { op: 'and', match: false, children: [
    t('is a person', true),
    { op: 'and', match: false, children: [t('in AllStaff', true), { op: 'not', say: 'not disabled', match: false, children: [t('disabled', true)] }] },
    t('has mail', false),
  ] };
  assert.deepEqual(blockers(root).map((n) => n.say), ['not disabled', 'has mail']);
});

test('a failed OR is one reason, and a match has none', () => {
  const or = { op: 'or', say: 'any of these', match: false, children: [t('a', false), t('b', false)] };
  assert.deepEqual(blockers({ op: 'and', match: false, children: [or] }), [or]);
  assert.deepEqual(blockers({ op: 'and', match: true, children: [] }), []);
});

test('valuesFor matches attribute names case-insensitively', () => {
  const values = [{ name: 'memberOf', values: [{ text: 'CN=Ops' }] }];
  assert.deepEqual(valuesFor(values, 'MEMBEROF'), [{ text: 'CN=Ops' }]);
  assert.deepEqual(valuesFor(values, 'mail'), []);
  assert.deepEqual(valuesFor(undefined, 'mail'), []);
});
