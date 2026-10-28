import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loginSummary, containerPath, hostOf, plural, rdnValue, splitDN, unescapeValue } from '../static/js/format.js';

const step = (id, status, title = id) => ({ id, status, title });

test('summary names the first failing step and the app that refuses', () => {
  const s = loginSummary([step('user', 'ok'), step('bind', 'ok'), step('groups', 'fail', 'Verify group membership')], 'Gitea');
  assert.equal(s.status, 'fail');
  assert.equal(s.text, 'Gitea would refuse this login at: Verify group membership');
});

test('summary says the password was not tested when the bind was skipped', () => {
  const s = loginSummary([step('user', 'ok'), step('bind', 'skipped'), step('groups', 'ok')], 'Gitea');
  assert.equal(s.status, 'warn');
  assert.match(s.text, /password was not tested/);
});

test('summary counts warnings on an otherwise working login', () => {
  const s = loginSummary([step('user', 'ok'), step('bind', 'ok'), step('groups', 'warn'), step('attributes', 'warn')], 'Open WebUI');
  assert.deepEqual(s, { status: 'warn', text: 'Open WebUI would accept this login, with 2 warnings' });
});

test('summary reports success when every step passed', () => {
  assert.deepEqual(loginSummary([step('user', 'ok'), step('bind', 'ok'), step('groups', 'skipped')], 'Generic'),
    { status: 'ok', text: 'The login would succeed' });
});

test('container path drops the domain and reads top-down', () => {
  assert.equal(containerPath('CN=Ops,OU=Groups,DC=corp,DC=local'), 'Groups');
  assert.equal(containerPath('CN=x,OU=Teams,OU=Groups,DC=corp,DC=local'), 'Groups / Teams');
  assert.equal(containerPath('CN=x,CN=Users,DC=corp,DC=local'), 'Users');
  assert.equal(containerPath('cn=devs,ou=groups,dc=example,dc=org'), 'groups');
  assert.equal(containerPath('CN=x,DC=corp,DC=local'), '');
  assert.equal(containerPath('CN=a\\,b,OU=R\\&D,DC=corp'), 'R&D');
});

test('host is taken from an LDAP URL', () => {
  assert.equal(hostOf('ldaps://TDA02.ADVANTECH.CORP:636'), 'TDA02.ADVANTECH.CORP');
  assert.equal(hostOf('ldap://127.0.0.1:3389'), '127.0.0.1');
  assert.equal(hostOf('ldap://[::1]:389'), '::1');
  assert.equal(hostOf('not a url'), 'not a url');
});

test('plural adds an s except for one', () => {
  assert.equal(plural(1, 'group'), '1 group');
  assert.equal(plural(4, 'group'), '4 groups');
  assert.equal(plural(0, 'warning'), '0 warnings');
});

test('summary keeps warnings visible when the password was not tested', () => {
  const s = loginSummary([step('user', 'warn'), step('bind', 'skipped'), step('groups', 'ok')], 'Gitea');
  assert.equal(s.status, 'warn');
  assert.match(s.text, /password was not tested/);
  assert.match(s.text, /1 warning\b/);
});

test('rdnValue decodes AD-style character escapes', () => {
  assert.equal(rdnValue('CN=Smith\\, John,OU=Users,DC=corp,DC=local'), 'Smith, John');
  assert.equal(rdnValue('CN=a\\+b\\=c\\\\d,OU=x'), 'a+b=c\\d');
});

test('rdnValue decodes OpenLDAP-style hex escapes', () => {
  assert.equal(rdnValue('cn=Smith\\2C John,ou=people,dc=example,dc=org'), 'Smith, John');
  assert.equal(rdnValue('cn=\\23hash\\20,ou=x'), '#hash ');
});

test('consecutive hex escapes form one UTF-8 character', () => {
  assert.equal(rdnValue('cn=J\\C3\\BCrgen,ou=x'), 'Jürgen');
  assert.equal(rdnValue('cn=\\E7\\8E\\8B\\E5\\B0\\8F\\E6\\98\\8E,ou=x'), '王小明');
});

test('container path decodes hex escapes too', () => {
  assert.equal(containerPath('cn=x,ou=R\\26D,ou=J\\C3\\BCrgen\\2C Team,dc=example,dc=org'), 'Jürgen, Team / R&D');
});

test('unescaped non-ASCII text passes through', () => {
  assert.equal(rdnValue('CN=王小明,OU=台北'), '王小明');
  assert.equal(unescapeValue('emoji 🙂 \\2C ok'), 'emoji 🙂 , ok');
});

test('malformed escapes do not throw', () => {
  assert.equal(unescapeValue('trailing\\'), 'trailing\\');
  assert.equal(unescapeValue('\\zz'), 'zz');
  assert.equal(unescapeValue('\\FF'), '�');
});

test('splitDN keeps escaped commas inside an RDN', () => {
  assert.deepEqual(splitDN('cn=Smith\\, John, ou=people,dc=example'), ['cn=Smith\\, John', 'ou=people', 'dc=example']);
  assert.deepEqual(splitDN('cn=Smith\\2C John,dc=example'), ['cn=Smith\\2C John', 'dc=example']);
});
