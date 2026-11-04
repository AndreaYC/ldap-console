import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseLdapUrl, isGlobalCatalog, domainOf, domainName, outsideDomain, gcBlind, gcBlindKind, presetBlind,
  gcNote, gcSearchWarning, gcGroupsWarning, gcMemberOfWarning, gcMembersWarning, gcPeopleWarning,
} from '../static/js/catalog.js';
import { presets, fromFilter } from '../static/js/conditions.js';

const base = 'DC=EXAMPLE,DC=CORP';
const gc = { isAD: true, url: 'ldaps://DC1.EXAMPLE.CORP:3269', baseDN: base };
const dc = { isAD: true, url: 'ldaps://DC1.EXAMPLE.CORP:636', baseDN: base };
const childUser = 'CN=Anna,OU=Users,DC=EU,DC=EXAMPLE,DC=CORP';
const ownUser = 'CN=Bob,OU=Users,DC=EXAMPLE,DC=CORP';

test('parseLdapUrl fills the default port from the scheme', () => {
  assert.deepEqual(parseLdapUrl('ldaps://dc1'), { secure: true, host: 'dc1', port: 636 });
  assert.deepEqual(parseLdapUrl('LDAP://dc1:3268/'), { secure: false, host: 'dc1', port: 3268 });
  assert.deepEqual(parseLdapUrl('ldaps://[fe80::1]:3269'), { secure: true, host: '[fe80::1]', port: 3269 });
  assert.deepEqual(parseLdapUrl('ldap://[fe80::1]'), { secure: false, host: '[fe80::1]', port: 389 });
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldaps://[fe80::1]:3269' }), true);
  assert.equal(parseLdapUrl('https://dc1'), null);
  assert.equal(parseLdapUrl(undefined), null);
});

test('isGlobalCatalog is true only for AD on port 3268 or 3269', () => {
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldap://dc1:3268' }), true);
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldaps://dc1:3269' }), true);
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldaps://dc1:636' }), false);
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldap://dc1:389' }), false);
  assert.equal(isGlobalCatalog({ isAD: true, url: 'ldaps://dc1' }), false);
  assert.equal(isGlobalCatalog({ isAD: false, url: 'ldaps://ldap.example.com:3269' }), false);
  assert.equal(isGlobalCatalog({ isAD: true, url: 'not a url :3269' }), false);
  assert.equal(isGlobalCatalog({ isAD: true, url: '' }), false);
  assert.equal(isGlobalCatalog(null), false);
});

test('domainOf keeps only the trailing DC components, lower-cased', () => {
  assert.equal(domainOf('OU=x,DC=Example, DC=Corp'), 'dc=example,dc=corp');
  assert.equal(domainOf('CN=a\\,DC=fake,DC=corp'), 'dc=corp', 'an escaped comma is part of the name');
  assert.equal(domainOf('CN=x,OU=y'), '');
  assert.equal(domainName(childUser), 'EU.EXAMPLE.CORP');
});

test('outsideDomain compares domains, not the rest of the DN', () => {
  assert.equal(outsideDomain(ownUser, base), false, 'same domain');
  assert.equal(outsideDomain('OU=x,DC=EXAMPLE,DC=CORP', base), false, 'an OU inside the domain');
  assert.equal(outsideDomain(childUser, base), true, 'child domain');
  assert.equal(outsideDomain('CN=c,DC=ACN,DC=EXAMPLE,DC=CORP', 'DC=EU,DC=EXAMPLE,DC=CORP'), true, 'sibling domain');
  assert.equal(outsideDomain('cn=bob,ou=users,dc=example,dc=corp', base), false, 'case differs');
  assert.equal(outsideDomain('cn=a,DC=eu,dc=Example,DC=corp', base), true, 'case differs, child domain');
  assert.equal(outsideDomain('', base), false, 'empty DN');
  assert.equal(outsideDomain(childUser, ''), false, 'empty base');
  assert.equal(outsideDomain(null, undefined), false);
});

test('only lockout and admin-flag conditions are blind on the Global Catalog', () => {
  assert.equal(gcBlind({ k: 'locked' }), true);
  assert.equal(gcBlind({ k: 'admin' }), true);
  assert.equal(gcBlind({ k: 'field', attr: 'lockouttime', op: 'gte', value: '5' }), true);
  assert.equal(gcBlind({ k: 'raw', src: '(|(adminCount=1)(cn=x))' }), true);
  for (const k of ['disabled', 'idle', 'neverExpires', 'neverLoggedIn', 'empty', 'group']) assert.equal(gcBlind({ k }), false, k);
  assert.equal(gcBlind({ k: 'field', attr: 'mail', op: 'has' }), false);
  assert.equal(gcBlind({ k: 'raw', src: '(description=adminCount is set)' }), false);
  assert.deepEqual(['locked', 'admin', 'disabled', 'empty'].map(gcBlindKind), [true, true, false, false]);
});

test('exactly the Locked out and Protected admins views are unavailable on the Global Catalog', () => {
  assert.deepEqual(presets.filter(presetBlind).map((p) => p.label), ['Locked out', 'Protected admins']);
});

test('gcNote names the Global Catalog port and the normal one', () => {
  assert.equal(gcNote(gc), 'Not available on the Global Catalog (port 3269) — connect on port 636');
  assert.match(gcNote({ isAD: true, url: 'ldap://dc1:3268' }), /port 3268\) — connect on port 389$/);
});

test('a pasted lockout or admin filter warns on the Global Catalog only', () => {
  const s = fromFilter('(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))');
  assert.match(gcSearchWarning(gc, s), /can't be trusted/);
  assert.match(gcSearchWarning(gc, fromFilter('(adminCount=1)')), /port 636/);
  assert.equal(gcSearchWarning(dc, s), null);
  assert.equal(gcSearchWarning(gc, fromFilter('(userAccountControl:1.2.840.113556.1.4.803:=2)')), null);
});

test('group results warn only when a group from another domain is listed', () => {
  const own = { kind: 'group', dn: 'CN=g,DC=EXAMPLE,DC=CORP' };
  const child = { kind: 'group', dn: 'CN=g,DC=EU,DC=EXAMPLE,DC=CORP' };
  assert.match(gcGroupsWarning(gc, [own, child]), /outside EXAMPLE\.CORP only show members if they are universal/);
  assert.equal(gcGroupsWarning(gc, [own]), null);
  assert.equal(gcGroupsWarning(gc, [{ kind: 'user', dn: childUser }]), null);
  assert.equal(gcGroupsWarning(dc, [child]), null);
});

test('a person or group in another domain gets one warning, on the Global Catalog only', () => {
  assert.match(gcMemberOfWarning(gc, childUser), /in EU\.EXAMPLE\.CORP.*Universal groups are complete/);
  assert.equal(gcMemberOfWarning(gc, ownUser), null);
  assert.equal(gcMemberOfWarning(dc, childUser), null);
  assert.equal(gcMemberOfWarning(null, childUser), null);
  assert.match(gcMembersWarning(gc, 'CN=g,DC=EU,DC=EXAMPLE,DC=CORP'), /universal group/);
  assert.equal(gcMembersWarning(gc, 'CN=g,DC=EXAMPLE,DC=CORP'), null);
});

test('the people warning names only the people outside the domain', () => {
  const people = [{ name: 'Anna', dn: childUser }, { name: 'Bob', dn: ownUser }, { name: 'Cai', dn: 'CN=Cai,DC=ACN,DC=EXAMPLE,DC=CORP' }];
  const w = gcPeopleWarning(gc, people);
  assert.match(w, /^Anna, Cai are outside EXAMPLE\.CORP/);
  assert.doesNotMatch(w, /Bob/);
  assert.match(gcPeopleWarning(gc, people.slice(0, 1)), /^Anna is outside/);
  assert.equal(gcPeopleWarning(gc, [people[1]]), null);
  assert.equal(gcPeopleWarning(dc, people), null);
});
