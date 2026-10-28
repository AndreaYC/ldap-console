let token = '';

async function call(url, init) {
  const res = await fetch(url, init);
  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

function get(path, params = {}) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
  }
  return call(url, { headers: { Accept: 'application/json' } });
}

// post sends the per-launch token the server requires on every POST.
function post(path, body) {
  return call(new URL(path, location.origin), {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Console-Token': token },
    body: JSON.stringify(body),
  });
}

export const api = {
  info: async () => {
    const info = await get('/api/info');
    token = info.token;
    return info;
  },
  connect: (settings) => post('/api/connect', settings),
  disconnect: () => post('/api/disconnect', {}),
  checkLogin: (check) => post('/api/check-login', check),
  children: (dn) => get('/api/children', { dn }),
  entry: (dn) => get('/api/entry', { dn }),
  search: (params) => get('/api/search', params),
  find: (q) => get('/api/find', { q }),
  groups: (base) => get('/api/groups', { base }),
  userGroups: (dn) => get('/api/user-groups', { dn }),
  groupMembers: (dn, nested) => get('/api/group-members', { dn, nested: nested ? 'true' : '' }),
};
