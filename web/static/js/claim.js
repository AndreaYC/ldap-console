// Stale-response guard. Pure: no DOM access, so it runs under node --test.
//
// Views render into a shared element after an await. Without a guard, a
// slow response for an earlier navigation lands after a newer one and
// overwrites it. claim(el) marks a new render into el and returns a check
// that stays true only until the next claim on the same element.

const claims = new WeakMap();

export function claim(el) {
  const token = {};
  claims.set(el, token);
  return () => claims.get(el) === token;
}
