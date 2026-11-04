// What the App login wizard produces for each application. Pure: no DOM
// access, so it runs under node --test.
import { buildSettings, defaultOptions } from './filters.js';
import { parseLdapUrl, isGlobalCatalog } from './catalog.js';

export const appInfo = {
  gitea: {
    name: 'Gitea',
    desc: 'Self-hosted Git. Settings go into an authentication source.',
    where: 'In Gitea: Site Administration › Authentication Sources › Add Authentication Source › LDAP (via BindDN).',
  },
  openwebui: {
    name: 'Open WebUI',
    desc: 'AI chat. Settings are environment variables.',
    where: 'In Open WebUI’s environment (.env file or docker compose), then restart it. Also set ENABLE_LDAP=true and the server and bind account.',
  },
  generic: {
    name: 'Other app',
    desc: 'Any app that asks for a user filter and a search base.',
    where: 'Field names differ between apps; the usual name of each is shown under it.',
  },
};

// wizardDefaults is a fresh wizard: everyone with an active account may log in.
export function wizardDefaults(isAD) {
  return { step: 1, app: 'gitea', who: 'everyone', groups: [], admins: [], ...defaultOptions(isAD) };
}

// needsGroups is true while "only members of certain groups" is chosen
// but no group is: buildSettings reads an empty list as everyone, so the
// wizard must not produce settings in this state.
export function needsGroups(state) {
  return state.who === 'groups' && state.groups.length === 0;
}

// optionsFrom turns wizard state into buildSettings options.
export function optionsFrom(state) {
  return {
    ...state,
    groups: state.who === 'groups' ? state.groups : [],
    adminGroups: state.app === 'gitea' ? state.admins : [],
  };
}

// settingRows lists what to paste into the app: plain wording, the app's
// own name for the setting, and the value. Gitea requires a search base,
// so an empty one becomes the connection's base DN.
export function settingRows(app, s, baseDN) {
  const base = s.generic.userBase || baseDN;
  switch (app) {
    case 'gitea':
      return [
        { plain: 'Where to look for users', original: 'User Search Base', value: base },
        { plain: 'Which accounts can log in', original: 'User Filter', value: s.gitea.userFilter },
        { plain: 'Who is an admin', original: 'Admin Filter', value: s.gitea.adminFilter },
        { plain: 'Where the email address is', original: 'Email Attribute', value: s.gitea.emailAttr },
      ];
    case 'openwebui':
      return [
        { plain: 'Where to look for users', original: 'LDAP_SEARCH_BASE', value: base },
        { plain: 'What people type to log in', original: 'LDAP_ATTRIBUTE_FOR_USERNAME', value: s.openwebui.usernameAttr },
        { plain: 'Where the email address is', original: 'LDAP_ATTRIBUTE_FOR_MAIL', value: s.openwebui.emailAttr },
        { plain: 'Extra conditions', original: 'LDAP_SEARCH_FILTERS', value: s.openwebui.searchFilters },
      ];
  }
  return [
    { plain: 'Where to look for users', original: 'User Search Base', value: base },
    { plain: 'Which accounts can log in', original: 'User Filter', value: s.generic.userFilter },
    { plain: 'Where to look for groups', original: 'Group Search Base', value: s.generic.groupBase || baseDN },
    { plain: 'How to find a user’s groups', original: 'Group Filter', value: s.generic.groupFilter },
  ];
}

// copyAllText is every row in one paste: environment lines for Open WebUI,
// "Name: value" lines otherwise. Empty settings are left out.
export function copyAllText(app, rows) {
  const filled = rows.filter((r) => r.value);
  if (app === 'openwebui') return filled.map((r) => `${r.original}="${r.value.replaceAll('"', '\\"')}"`).join('\n');
  return filled.map((r) => `${r.original}: ${r.value}`).join('\n');
}

// checkPayload is the login test request for these settings.
export function checkPayload(app, s) {
  switch (app) {
    case 'gitea':
      return { app, userBase: s.gitea.userBase, userFilter: s.gitea.userFilter, adminFilter: s.gitea.adminFilter, emailAttr: s.gitea.emailAttr };
    case 'openwebui':
      return { app, userBase: s.openwebui.userBase, usernameAttr: s.openwebui.usernameAttr, emailAttr: s.openwebui.emailAttr, searchFilters: s.openwebui.searchFilters };
  }
  return { app: 'generic', userBase: s.generic.userBase, userFilter: s.generic.userFilter, groupBase: s.generic.groupBase, groupFilter: s.generic.groupFilter };
}

// settingsFor is buildSettings for wizard state.
export function settingsFor(state) {
  return buildSettings(optionsFrom(state));
}

// forestHint explains, for an AD connection on a domain controller's normal
// port, that people in other domains of the forest (e.g. a child domain)
// can't be found there, and names the Global Catalog address that can.
// It returns null when the connection is already a Global Catalog, isn't
// AD, or its URL can't be read.
export function forestHint(info) {
  if (!info || !info.isAD || isGlobalCatalog(info)) return null;
  const u = parseLdapUrl(info.url);
  if (!u) return null;
  const { secure, host, port } = u;
  const gc = secure ? `ldaps://${host}:3269` : `ldap://${host}:3268`;
  return {
    gc,
    text: `People in other domains of this forest (for example a child domain) can't log in through port ${port}: it only searches ${host}'s own domain. ` +
      `If they need to, point the app's server at the Global Catalog, ${gc}, with the same search base and bind account.`,
  };
}
