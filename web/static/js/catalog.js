// What an AD Global Catalog connection can't answer. Pure: no DOM access,
// so it runs under node --test.
import { splitDN } from './format.js';
//
// A Global Catalog (port 3268, or 3269 over TLS) holds every domain of the
// forest but only part of each entry: lockoutTime and adminCount are never
// there, and for domains other than the connected DC's own, member is kept
// only on universal groups.

// parseLdapUrl reads scheme, host and port (the default when none is given)
// from an ldap:// or ldaps:// URL, or returns null. An IPv6 host keeps its
// brackets, so it can be put back into a URL as is.
export function parseLdapUrl(url) {
  const m = /^(ldaps?):\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i.exec(url || '');
  if (!m) return null;
  const secure = m[1].toLowerCase() === 'ldaps';
  return { secure, host: m[2], port: m[3] ? Number(m[3]) : secure ? 636 : 389 };
}

const gcPorts = new Set([3268, 3269]);

// isGlobalCatalog is true for an AD connection on a Global Catalog port.
export function isGlobalCatalog(info) {
  if (!info?.isAD) return false;
  const u = parseLdapUrl(info.url);
  return !!u && gcPorts.has(u.port);
}

// domainOf is a DN's trailing DC= components, lower-cased, e.g.
// "dc=eu,dc=example,dc=corp"; '' when it has none.
export function domainOf(dn) {
  const rdns = splitDN(String(dn || '')).map((r) => r.replace(/\s*=\s*/, '='));
  const tail = [];
  for (let i = rdns.length - 1; i >= 0 && /^dc=/i.test(rdns[i]); i--) tail.unshift(rdns[i].toLowerCase());
  return tail.join(',');
}

// domainName is a DN's domain as people write it, e.g. "EXAMPLE.CORP".
export function domainName(dn) {
  return domainOf(dn).split(',').filter(Boolean).map((r) => r.slice(3).toUpperCase()).join('.');
}

// outsideDomain is true when dn belongs to a different domain than baseDN.
// Empty or domain-less input is never outside: there is nothing to compare.
export function outsideDomain(dn, baseDN) {
  const a = domainOf(dn);
  const b = domainOf(baseDN);
  return !!a && !!b && a !== b;
}

// Conditions that read attributes the Global Catalog does not return.
const blindKinds = new Set(['locked', 'admin']);
const blindAttrs = /\b(lockoutTime|adminCount)\s*(:|~=|<=|>=|=)/i;

// gcBlind is true for a condition the Global Catalog can't answer: a
// locked-out or protected-admin chip, or a field or raw clause on the same
// attributes.
export function gcBlind(c) {
  if (blindKinds.has(c.k)) return true;
  if (c.k === 'field') return /^(lockoutTime|adminCount)$/i.test(c.attr || '');
  if (c.k === 'raw') return blindAttrs.test(c.src || '');
  return false;
}

// gcBlindKind is true for an "+ Add filter" entry or saved view kind that
// can't work on the Global Catalog.
export function gcBlindKind(k) {
  return blindKinds.has(k);
}

// presetBlind is true for a saved view that can't work on the Global Catalog.
export function presetBlind(p) {
  return (p.search.conds || []).some(gcBlind);
}

// normalPort is the domain controller port that has every attribute.
export function normalPort(info) {
  return parseLdapUrl(info?.url)?.secure === false ? 389 : 636;
}

// gcNote is the short reason shown next to something the Global Catalog
// can't do.
export function gcNote(info) {
  const u = parseLdapUrl(info?.url);
  return `Not available on the Global Catalog (port ${u?.port ?? 3269}) — connect on port ${normalPort(info)}`;
}

// gcSearchWarning is the line shown over results whose search uses a
// condition the Global Catalog can't answer, or null.
export function gcSearchWarning(info, search) {
  if (!isGlobalCatalog(info) || !(search.conds || []).some(gcBlind)) return null;
  return `This search uses lockout or admin flags, which the Global Catalog never returns, so the result can't be trusted. Connect on port ${normalPort(info)} instead.`;
}

// gcGroupsWarning is the line shown over results that list groups from
// another domain, whose members the Global Catalog keeps only for
// universal groups, or null.
export function gcGroupsWarning(info, rows) {
  if (!isGlobalCatalog(info) || !rows.some((e) => e.kind === 'group' && outsideDomain(e.dn, info.baseDN))) return null;
  return `On the Global Catalog, groups outside ${domainName(info.baseDN)} only show members if they are universal groups.`;
}

// gcMemberOfWarning is the line shown over one person's group list when
// they are in another domain, or null.
export function gcMemberOfWarning(info, dn) {
  if (!isGlobalCatalog(info) || !outsideDomain(dn, info.baseDN)) return null;
  return `This account is in ${domainName(dn)}, outside ${domainName(info.baseDN)}: the Global Catalog may be missing its global and domain-local groups from ${domainName(dn)}. Universal groups are complete.`;
}

// gcMembersWarning is the line shown over a group's member list when the
// group is in another domain, or null.
export function gcMembersWarning(info, dn) {
  if (!isGlobalCatalog(info) || !outsideDomain(dn, info.baseDN)) return null;
  return `This group is outside ${domainName(info.baseDN)}: the Global Catalog only shows its members if it is a universal group.`;
}

// gcPeopleWarning is one line naming the people (each { name, dn }) whose
// group lists may be incomplete on the Global Catalog, or null.
export function gcPeopleWarning(info, people) {
  if (!isGlobalCatalog(info)) return null;
  const out = people.filter((p) => outsideDomain(p.dn, info.baseDN));
  if (!out.length) return null;
  return `${out.map((p) => p.name).join(', ')} ${out.length === 1 ? 'is' : 'are'} outside ${domainName(info.baseDN)}: the Global Catalog may be missing ` +
    `global and domain-local groups from their own domain. Universal groups are complete.`;
}
