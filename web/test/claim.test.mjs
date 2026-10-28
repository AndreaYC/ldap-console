import { test } from 'node:test';
import assert from 'node:assert/strict';
import { claim } from '../static/js/claim.js';

test('only the latest claim on an element stays current', () => {
  const el = {};
  const first = claim(el);
  assert.equal(first(), true);
  const second = claim(el);
  assert.equal(first(), false);
  assert.equal(second(), true);
});

test('claims on different elements are independent', () => {
  const a = {};
  const b = {};
  const ca = claim(a);
  claim(b);
  assert.equal(ca(), true);
});

test('an out-of-order response is dropped', async () => {
  const el = { shown: null };
  const render = async (name, delay) => {
    const current = claim(el);
    await new Promise((r) => setTimeout(r, delay));
    if (current()) el.shown = name;
  };
  // A is requested first but answers last, as a slow entry would.
  await Promise.all([render('A', 30), render('B', 5)]);
  assert.equal(el.shown, 'B');
});
