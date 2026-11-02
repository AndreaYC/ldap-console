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
  ad: { label: 'Active Directory users (user)', clauses: ['(objectCategory=person)', '(objectClass=user)'] },
  inetOrgPerson: { label: 'LDAP people (inetOrgPerson)', clauses: ['(objectClass=inetOrgPerson)'] },
  posixAccount: { label: 'Unix accounts (posixAccount)', clauses: ['(objectClass=posixAccount)'] },
};

// Group schemas: how a group lists its members, for group filters.
export const groupSchemas = {
  ad: { label: 'AD groups, members listed by full path (group / member)', objectClass: 'group', memberAttr: 'member', byDN: true },
  groupOfNames: { label: 'LDAP groups, members listed by full path (groupOfNames / member)', objectClass: 'groupOfNames', memberAttr: 'member', byDN: true },
  groupOfUniqueNames: { label: 'LDAP groups, members listed by full path (groupOfUniqueNames / uniqueMember)', objectClass: 'groupOfUniqueNames', memberAttr: 'uniqueMember', byDN: true },
  posixGroup: { label: 'Unix groups, members listed by login name (posixGroup / memberUid)', objectClass: 'posixGroup', memberAttr: 'memberUid', byDN: false },
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
    warnings.push('Group conditions read each account\u2019s list of groups (memberOf). AD keeps it up to date; OpenLDAP only with the memberof overlay, otherwise nobody matches.');
  }
  if (o.nested && o.accounts !== 'ad') {
    warnings.push(`Including people in sub-groups (LDAP_MATCHING_RULE_IN_CHAIN, ${RULE_IN_CHAIN}) works on AD only.`);
  }
  if (o.excludeDisabled && o.accounts !== 'ad') {
    warnings.push('Leaving out disabled accounts reads AD\u2019s userAccountControl; other servers mark disabled accounts differently.');
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
