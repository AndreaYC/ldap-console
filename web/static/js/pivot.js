import { rdnValue } from './format.js';

// Bulk lookup helpers. Pure: no DOM access, so they run under node --test.

// parseNames splits pasted text into names: one per line, or separated by
// commas, semicolons or tabs. A line that looks like a DN ("CN=x,OU=y") is
// kept whole, since its commas are part of it. Duplicates (ignoring case)
// are dropped; order is kept.
export function parseNames(text) {
  const seen = new Set();
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const parts = /^\s*[A-Za-z][\w-]*=/.test(line) ? line.split(/[;\t]/) : line.split(/[,;\t]/);
    for (let p of parts) {
      p = p.trim();
      const key = p.toLowerCase();
      if (!p || seen.has(key)) continue;
      seen.add(key);
      out.push(p);
    }
  }
  return out;
}

// pivotGroups turns per-person results into one row per group: which of
// the found people are in it, and how. Rows are sorted by how many people
// share the group, then by name. cells[i] belongs to people[i]: the
// membership ({ direct, primary, via }) or null. Names that resolved to the
// same account ("alice" and "alice@corp.local") share one column.
export function pivotGroups(results) {
  const accounts = new Set();
  const people = results.filter((p) => {
    if (p.status !== 'found') return false;
    const key = (p.matches?.[0]?.dn || p.query).toLowerCase();
    if (accounts.has(key)) return false;
    accounts.add(key);
    return true;
  });
  const rows = new Map();
  people.forEach((p, i) => {
    for (const g of p.groups || []) {
      const key = g.dn.toLowerCase();
      let row = rows.get(key);
      if (!row) {
        row = { group: { dn: g.dn, name: g.name, kind: g.kind, groupType: g.groupType || '' }, cells: new Array(people.length).fill(null), count: 0, direct: 0 };
        rows.set(key, row);
      }
      if (row.cells[i]) continue;
      row.cells[i] = { direct: !!g.direct, primary: !!g.primary, via: g.via || [] };
      row.count++;
      if (g.direct) row.direct++;
    }
  });
  const sorted = [...rows.values()].sort((a, b) => b.count - a.count ||
    a.group.name.toLowerCase().localeCompare(b.group.name.toLowerCase()));
  return { people, rows: sorted };
}

// cellLabel is a cell's text in the table and in CSV exports.
export function cellLabel(cell) {
  if (!cell) return '';
  if (cell.primary) return 'primary';
  return cell.direct ? 'direct' : 'nested';
}

export const listHeader = ['input', 'status', 'account', 'accountDN', 'group', 'membership', 'via', 'groupDN'];

// listRows is the long CSV export: one row per person and group. A name
// that did not resolve, or an account in no group (the server then omits
// groups), still gets one row so every input shows up.
export function listRows(results) {
  return results.flatMap((p) => {
    if (p.status !== 'found') return [[p.query, p.status, '', '', '', '', '', '']];
    const who = [p.query, p.status, p.matches[0].name, p.matches[0].dn];
    const groups = p.groups || [];
    if (!groups.length) return [[...who, '', '', '', '']];
    return groups.map((g) => [...who, g.name, cellLabel(g), (g.via || []).map(rdnValue).join(' > '), g.dn]);
  });
}
