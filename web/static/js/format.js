// Pure text helpers, kept free of the DOM so they can be unit tested.

// splitDN splits on unescaped commas.
export function splitDN(dn) {
  const out = [];
  let cur = '';
  for (let i = 0; i < dn.length; i++) {
    const c = dn[i];
    if (c === '\\' && i + 1 < dn.length) { cur += c + dn[++i]; continue; }
    if (c === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const hexPair = /^[0-9a-fA-F]{2}$/;
const utf8 = new TextEncoder();

// unescapeValue decodes RFC 4514 escapes: "\," style (AD) and "\2C" style
// (OpenLDAP), where consecutive hex pairs form one UTF-8 sequence
// ("J\C3\BCrgen" -> "Jürgen"). Invalid UTF-8 becomes U+FFFD.
export function unescapeValue(s) {
  if (!s.includes('\\')) return s;
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      const pair = s.slice(i + 1, i + 3);
      if (hexPair.test(pair)) {
        bytes.push(parseInt(pair, 16));
        i += 2;
      } else {
        bytes.push(...utf8.encode(s[++i]));
      }
      continue;
    }
    const cp = s.codePointAt(i);
    if (cp > 0xffff) i++; // astral character: skip its low surrogate
    bytes.push(...utf8.encode(String.fromCodePoint(cp)));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// valueOfRDN returns the decoded value of one RDN ("OU=R\26D" -> "R&D").
function valueOfRDN(rdn) {
  const i = rdn.indexOf('=');
  return unescapeValue(i < 0 ? rdn : rdn.slice(i + 1));
}

// rdnValue returns the value of the first RDN ("CN=Alice,OU=x" -> "Alice").
export function rdnValue(dn) {
  return valueOfRDN(splitDN(dn)[0] || dn);
}

// containerPath is where an entry lives, top-down and without the domain:
// "CN=x,OU=Teams,OU=Groups,DC=corp,DC=local" -> "Groups / Teams".
export function containerPath(dn) {
  return splitDN(dn).slice(1).filter((r) => !/^dc=/i.test(r)).map(valueOfRDN).reverse().join(' / ');
}

// hostOf returns the host of an ldap:// or ldaps:// URL.
export function hostOf(url) {
  const m = /^ldaps?:\/\/(\[[^\]]+\]|[^/:]+)/i.exec(url || '');
  return m ? m[1].replace(/^\[|\]$/g, '') : url;
}

export function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

// loginSummary turns login test steps into one line: where the login breaks,
// or whether it would work.
export function loginSummary(steps, appLabel) {
  const who = appLabel === 'Generic' ? 'The application' : appLabel;
  const failed = steps.find((s) => s.status === 'fail');
  if (failed) return { status: 'fail', text: `${who} would refuse this login at: ${failed.title}` };
  const warnings = steps.filter((s) => s.status === 'warn').length;
  if (steps.some((s) => s.id === 'bind' && s.status === 'skipped')) {
    const also = warnings ? `, and there ${warnings === 1 ? 'is' : 'are'} ${plural(warnings, 'warning')} below` : '';
    return { status: 'warn', text: `The user is found, but the password was not tested${also}. Enter it to test the sign-in too` };
  }
  if (warnings) return { status: 'warn', text: `${who} would accept this login, with ${plural(warnings, 'warning')}` };
  return { status: 'ok', text: appLabel === 'Generic' ? 'The login would succeed' : `${appLabel} would accept this login` };
}
