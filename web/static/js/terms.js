// The UI's vocabulary: plain English first, the LDAP or application term it
// stands for second. The original stays visible so a label can be matched
// against an application's settings page and searched for. Pure: no DOM
// access, so it runs under node --test; dom.js renders it.

export const terms = {
  // where to search
  base: ['Where to search', 'Base DN'],
  userBase: ['Where to look for users', 'User Search Base'],
  groupBase: ['Where to look for groups', 'Group Search Base'],
  dn: ['Full path', 'DN'],
  container: ['Location', 'OU'],
  scope: ['How deep', 'Scope'],

  // conditions
  filter: ['Conditions', 'LDAP filter'],
  userFilter: ['Which accounts can log in', 'User Filter'],
  groupFilter: ['How to find a user’s groups', 'Group Filter'],
  adminFilter: ['Who is an admin', 'Admin Filter'],
  restrictedFilter: ['Who is restricted', 'Restricted Filter'],
  verifyGroups: ['Only allow members of these groups', 'Verify group membership filter'],
  searchFilters: ['Extra conditions', 'Search Filters'],
  attributes: ['Columns to show', 'Attributes'],

  // accounts
  bindAccount: ['Sign in as', 'Bind DN'],
  loginAttr: ['What users type to log in', 'username attribute'],
  emailAttr: ['Where the email address is', 'Email Attribute'],
  accountType: ['Kind of account', 'objectClass'],
  disabled: ['Disabled', 'ACCOUNTDISABLE'],
  groupMemberAttr: ['Group field that lists its members', 'Group Attribute Containing List Of Users'],
  userAttrInGroup: ['Account field the group lists', 'User Attribute Listed In Group'],
  groupAttr: ['Account field that lists its groups', 'Attribute for Groups'],

  // membership
  direct: ['Directly', 'direct'],
  nested: ['Through a sub-group', 'nested'],
  primary: ['Default group', 'primary group'],
  inChain: ['Include people in sub-groups', 'LDAP_MATCHING_RULE_IN_CHAIN'],
  groupSchema: ['How groups list their members', 'group objectClass'],
  groupType: ['Type', 'groupType'],
};

// termText is "Plain (Original)", for places that take only text: options,
// placeholders, titles.
export function termText(key) {
  const [plain, original] = terms[key];
  return `${plain} (${original})`;
}
