async function get(path, params = {}) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
  }
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

export const api = {
  info: () => get('/api/info'),
  children: (dn) => get('/api/children', { dn }),
  entry: (dn) => get('/api/entry', { dn }),
  search: (params) => get('/api/search', params),
  find: (q) => get('/api/find', { q }),
  groups: (base) => get('/api/groups', { base }),
  userGroups: (dn) => get('/api/user-groups', { dn }),
  groupMembers: (dn, nested) => get('/api/group-members', { dn, nested: nested ? 'true' : '' }),
};
