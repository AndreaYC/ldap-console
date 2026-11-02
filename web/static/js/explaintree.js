// Reading an explanation tree. Pure: no DOM access, so it runs under node --test.

// blockers returns the parts of a failed filter that stop the account
// matching: inside a failed "all of these", each failed part (looking
// deeper while that part is itself an "all of these"); a failed "any of
// these", "not" or single test is a reason in its own right.
export function blockers(node) {
  if (!node || node.match) return [];
  if (node.op !== 'and') return [node];
  return node.children.filter((c) => !c.match).flatMap(blockers);
}

// valuesFor returns the account's values of attribute name, matched
// case-insensitively; [] when it has none or the bind account can't read it.
export function valuesFor(values, name) {
  if (!name) return [];
  return (values || []).find((v) => v.name.toLowerCase() === name.toLowerCase())?.values || [];
}
