import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSettings, defaultOptions, escapeFilterValue } from '../static/js/filters.js';

const eng = 'CN=Engineering,OU=Groups,DC=corp,DC=local';
const ops = 'CN=Ops (EU),OU=Groups,DC=corp,DC=local';

test('escapeFilterValue escapes RFC 4515 metacharacters', () => {
  assert.equal(escapeFilterValue('CN=Smith\\, J (x)*'), 'CN=Smith\\5c, J \\28x\\29\\2a');
});

test('AD defaults: person, login, not disabled, has mail', () => {
  const s = buildSettings(defaultOptions(true));
  assert.equal(s.generic.userFilter,
    '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*))');
  assert.equal(s.gitea.userFilter,
    '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%[1]s)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*))');
  assert.equal(s.preview,
    '(&(objectCategory=person)(objectClass=user)(sAMAccountName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*))');
  assert.equal(s.generic.groupFilter, '(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={dn}))');
  assert.equal(s.openwebui.usernameAttr, 'sAMAccountName');
  assert.equal(s.openwebui.searchFilters,
    '(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*)');
  assert.deepEqual(s.warnings, []);
});

test('allowed groups become an escaped memberOf OR, nested on AD', () => {
  const s = buildSettings({ ...defaultOptions(true), groups: [eng, ops], excludeDisabled: false, requireEmail: false });
  const clause = `(|(memberOf:1.2.840.113556.1.4.1941:=${eng})(memberOf:1.2.840.113556.1.4.1941:=CN=Ops \\28EU\\29,OU=Groups,DC=corp,DC=local))`;
  assert.equal(s.generic.userFilter, `(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})${clause})`);
  assert.equal(s.openwebui.searchFilters, `(objectCategory=person)(objectClass=user)${clause}`);
});

test('one direct group needs no OR; admin groups fill the Gitea admin filter', () => {
  const s = buildSettings({ ...defaultOptions(true), nested: false, groups: [eng], adminGroups: [ops], excludeDisabled: false, requireEmail: false });
  assert.equal(s.gitea.userFilter, `(&(objectCategory=person)(objectClass=user)(sAMAccountName=%[1]s)(memberOf=${eng}))`);
  assert.equal(s.gitea.adminFilter, '(memberOf=CN=Ops \\28EU\\29,OU=Groups,DC=corp,DC=local)');
});

test('Gitea user filter doubles a literal % for fmt.Sprintf; the admin filter does not', () => {
  const pct = 'CN=100% Club,OU=Groups,DC=corp,DC=local';
  const s = buildSettings({ ...defaultOptions(true), nested: false, groups: [pct], adminGroups: [pct], excludeDisabled: false, requireEmail: false });
  assert.match(s.gitea.userFilter, /CN=100%% Club/);
  assert.match(s.gitea.userFilter, /=%\[1\]s\)/);
  assert.equal(s.gitea.adminFilter, `(memberOf=${pct})`);
});

test('OpenLDAP defaults and posixGroup group filter', () => {
  const o = { ...defaultOptions(false), requireEmail: false };
  assert.equal(buildSettings(o).generic.userFilter, '(&(objectClass=inetOrgPerson)(uid={username}))');
  assert.equal(buildSettings(o).generic.groupFilter, '(&(objectClass=groupOfNames)(member={dn}))');
  assert.equal(buildSettings({ ...o, groupSchema: 'posixGroup' }).generic.groupFilter, '(&(objectClass=posixGroup)(memberUid={username}))');
});

test('AD-only choices on other servers produce warnings', () => {
  const s = buildSettings({ ...defaultOptions(false), groups: [eng], nested: true, excludeDisabled: true });
  assert.equal(s.warnings.length, 3);
});
