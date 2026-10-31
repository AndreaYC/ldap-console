import { test } from 'node:test';
import assert from 'node:assert/strict';
import { terms, termText } from '../static/js/terms.js';

test('every glossary entry pairs plain wording with the original term', () => {
  for (const [key, pair] of Object.entries(terms)) {
    assert.equal(pair.length, 2, key);
    const [plain, original] = pair;
    assert.ok(plain && original && plain !== original, key);
  }
});

test('termText puts the original term in parentheses', () => {
  assert.equal(termText('base'), 'Where to search (Base DN)');
  assert.equal(termText('nested'), 'Through a sub-group (nested)');
});
