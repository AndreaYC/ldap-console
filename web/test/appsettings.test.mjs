import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wizardDefaults, settingsFor, settingRows, copyAllText, checkPayload, needsGroups, forestHint } from '../static/js/appsettings.js';

const base = 'DC=corp,DC=local';
const eng = 'CN=Engineering,OU=Groups,DC=corp,DC=local';

test('a fresh wizard lets every active AD account in', () => {
  const s = settingsFor(wizardDefaults(true));
  assert.doesNotMatch(s.generic.userFilter, /memberOf/);
  assert.match(s.generic.userFilter, /!\(userAccountControl/);
});

test('groups only count when "only members" is chosen, admins only for Gitea', () => {
  const st = { ...wizardDefaults(true), groups: [eng], admins: [eng] };
  assert.doesNotMatch(settingsFor(st).generic.userFilter, /memberOf/);
  assert.match(settingsFor({ ...st, who: 'groups' }).generic.userFilter, /memberOf:1\.2\.840\.113556\.1\.4\.1941:=CN=Engineering/);
  assert.equal(settingsFor({ ...st, app: 'gitea' }).gitea.adminFilter, `(memberOf:1.2.840.113556.1.4.1941:=${eng})`);
  assert.equal(settingsFor({ ...st, app: 'openwebui' }).gitea.adminFilter, '');
});

test('Gitea rows fill an empty search base with the connection base DN', () => {
  const rows = settingRows('gitea', settingsFor({ ...wizardDefaults(true), app: 'gitea' }), base);
  assert.deepEqual(rows.map((r) => r.original), ['User Search Base', 'User Filter', 'Admin Filter', 'Email Attribute']);
  assert.equal(rows[0].value, base);
  assert.match(rows[1].value, /sAMAccountName=%\[1\]s/);
});

test('copy all writes env lines for Open WebUI and skips empty settings', () => {
  const st = { ...wizardDefaults(true), app: 'openwebui' };
  const text = copyAllText('openwebui', settingRows('openwebui', settingsFor(st), base));
  assert.match(text, /^LDAP_SEARCH_BASE="DC=corp,DC=local"$/m);
  assert.match(text, /^LDAP_ATTRIBUTE_FOR_USERNAME="sAMAccountName"$/m);
  assert.match(text, /^LDAP_SEARCH_FILTERS="\(objectCategory=person\)/m);
  const gitea = copyAllText('gitea', settingRows('gitea', settingsFor({ ...wizardDefaults(true), app: 'gitea' }), base));
  assert.doesNotMatch(gitea, /Admin Filter/);
  assert.match(gitea, /^User Filter: \(&/m);
});

test('the login test gets exactly the fields its app uses', () => {
  const s = settingsFor(wizardDefaults(true));
  assert.deepEqual(Object.keys(checkPayload('gitea', s)), ['app', 'userBase', 'userFilter', 'adminFilter', 'emailAttr']);
  assert.deepEqual(Object.keys(checkPayload('openwebui', s)), ['app', 'userBase', 'usernameAttr', 'emailAttr', 'searchFilters']);
  assert.equal(checkPayload('generic', s).userFilter, s.generic.userFilter);
});

test('"only members of certain groups" with no group is flagged, never treated as everyone', () => {
  const st = { ...wizardDefaults(true), who: 'groups', groups: [] };
  assert.equal(needsGroups(st), true);
  assert.equal(needsGroups({ ...st, groups: [eng] }), false);
  assert.equal(needsGroups({ ...st, who: 'everyone' }), false);
});

test('forestHint suggests the Global Catalog for AD on a normal domain controller port', () => {
  assert.equal(forestHint({ isAD: true, url: 'ldaps://dc1.corp.local:636' }).gc, 'ldaps://dc1.corp.local:3269');
  assert.equal(forestHint({ isAD: true, url: 'ldaps://dc1.corp.local' }).gc, 'ldaps://dc1.corp.local:3269');
  assert.equal(forestHint({ isAD: true, url: 'ldap://dc1.corp.local:389' }).gc, 'ldap://dc1.corp.local:3268');
  assert.match(forestHint({ isAD: true, url: 'LDAPS://DC1:636' }).text, /port 636/);
});

test('forestHint stays quiet on a Global Catalog, on non-AD servers and on unreadable URLs', () => {
  assert.equal(forestHint({ isAD: true, url: 'ldaps://dc1.corp.local:3269' }), null);
  assert.equal(forestHint({ isAD: true, url: 'ldap://dc1.corp.local:3268' }), null);
  assert.equal(forestHint({ isAD: false, url: 'ldaps://ldap.example.com:636' }), null);
  assert.equal(forestHint({ isAD: true, url: '' }), null);
  assert.equal(forestHint(null), null);
});
