// Composes LDAP login settings for applications. Pure: no DOM access, so it
// runs under node --test.

export const RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'; // AD: transitive membership
export const RULE_BIT_AND = '1.2.840.113556.1.4.803';

// escapeFilterValue escapes an assertion value per RFC 4515, as the
// server's ldap.EscapeFilter does. Group DNs need it: "CN=R\, D" carries a
// backslash and names can contain parentheses or *.
export function escapeFilterValue(s) {
  return String(s).replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

// Account classes: the filter part that selects people.
export const accountClasses = {
  ad: { label: 'AD users', clauses: ['(objectCategory=person)', '(objectClass=user)'] },
  inetOrgPerson: { label: 'inetOrgPerson', clauses: ['(objectClass=inetOrgPerson)'] },
  posixAccount: { label: 'posixAccount', clauses: ['(objectClass=posixAccount)'] },
};

// Group schemas: how a group lists its members, for group filters.
export const groupSchemas = {
  ad: { label: 'AD group (member = user DN)', objectClass: 'group', memberAttr: 'member', byDN: true },
  groupOfNames: { label: 'groupOfNames (member = user DN)', objectClass: 'groupOfNames', memberAttr: 'member', byDN: true },
  groupOfUniqueNames: { label: 'groupOfUniqueNames (uniqueMember = user DN)', objectClass: 'groupOfUniqueNames', memberAttr: 'uniqueMember', byDN: true },
  posixGroup: { label: 'posixGroup (memberUid = login)', objectClass: 'posixGroup', memberAttr: 'memberUid', byDN: false },
};

export function defaultOptions(isAD) {
  return {
    accounts: isAD ? 'ad' : 'inetOrgPerson',
    loginAttr: isAD ? 'sAMAccountName' : 'uid',
    emailAttr: 'mail',
    userBase: '',
    groups: [], // DNs; members of any of them may log in. Empty = everyone
    adminGroups: [], // DNs; members are admins (Gitea)
    nested: isAD, // AD only: membership through nested groups counts
    excludeDisabled: isAD, // AD only
    requireEmail: true,
    groupSchema: isAD ? 'ad' : 'groupOfNames',
    groupBase: '',
  };
}

// Stands in for the login name until each application's dialect is applied.
const LOGIN = '\u0000login\u0000';
const USERDN = '\u0000dn\u0000';

function memberOfClause(dns, nested) {
  const attr = nested ? `memberOf:${RULE_IN_CHAIN}:` : 'memberOf';
  const parts = dns.map((dn) => `(${attr}=${escapeFilterValue(dn)})`);
  return parts.length > 1 ? `(|${parts.join('')})` : parts.join('');
}

// and joins single clauses; one clause needs no (&…).
function and(clauses) {
  return clauses.length === 1 ? clauses[0] : `(&${clauses.join('')})`;
}

// conditions are the clauses every login must satisfy besides the login
// name, account class first.
function conditions(o) {
  return [
    ...(accountClasses[o.accounts]?.clauses || []),
    o.groups.length ? memberOfClause(o.groups, o.nested) : '',
    o.excludeDisabled ? `(!(userAccountControl:${RULE_BIT_AND}:=2))` : '',
    o.requireEmail && o.emailAttr ? `(${o.emailAttr}=*)` : '',
  ].filter(Boolean);
}

// dialects render the placeholders the way each application fills them.
// Gitea runs only its user filter through fmt.Sprintf, so a literal % there
// must be %%; its admin and group filters are sent as written.
const dialects = {
  generic: (f) => f.replaceAll(LOGIN, '{username}').replaceAll(USERDN, '{dn}'),
  gitea: (f) => f.replaceAll('%', '%%').replaceAll(LOGIN, '%[1]s'),
};

// buildSettings composes each application's settings from the options.
// warnings explain choices that need something on the server side.
export function buildSettings(o) {
  const cond = conditions(o);
  const classes = accountClasses[o.accounts]?.clauses.length || 0;
  const user = and([...cond.slice(0, classes), `(${o.loginAttr}=${LOGIN})`, ...cond.slice(classes)]);

  const schema = groupSchemas[o.groupSchema] || groupSchemas.ad;
  const nestedGroups = o.nested && schema.byDN && schema.memberAttr === 'member';
  const memberAttr = schema.memberAttr + (nestedGroups ? `:${RULE_IN_CHAIN}:` : '');
  const group = `(&(objectClass=${schema.objectClass})(${memberAttr}=${schema.byDN ? USERDN : LOGIN}))`;

  const admin = o.adminGroups.length ? memberOfClause(o.adminGroups, o.nested) : '';

  const warnings = [];
  if (o.groups.length && o.accounts !== 'ad') {
    warnings.push('memberOf is maintained by AD; on OpenLDAP it needs the memberof overlay, or the filter matches no one.');
  }
  if (o.nested && o.accounts !== 'ad') {
    warnings.push(`The in-chain rule ${RULE_IN_CHAIN} (nested groups) works on AD only.`);
  }
  if (o.excludeDisabled && o.accounts !== 'ad') {
    warnings.push('userAccountControl exists on AD only; other servers lock accounts differently.');
  }

  return {
    preview: user.replaceAll(LOGIN, '*'), // every account that may log in
    warnings,
    generic: {
      userBase: o.userBase,
      userFilter: dialects.generic(user),
      groupBase: o.groupBase,
      groupFilter: dialects.generic(group),
    },
    gitea: {
      userBase: o.userBase,
      userFilter: dialects.gitea(user),
      adminFilter: admin,
      emailAttr: o.emailAttr,
    },
    // Open WebUI builds (&(<username attribute>=<login>)<search filters>).
    openwebui: {
      userBase: o.userBase,
      usernameAttr: o.loginAttr,
      emailAttr: o.emailAttr,
      searchFilters: cond.join(''),
    },
  };
}
