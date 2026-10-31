import { api } from './api.js';
import { h, nodes, errorBox, term } from './dom.js';

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', null, label), input, hint ? h('span', { class: 'muted hint' }, hint) : null);
}

// renderConnect draws the connection form, pre-filled from info.profile.
// The password is sent once for the bind and never stored.
export function renderConnect(el, info) {
  const p = info.profile || {};
  const url = h('input', { name: 'url', value: p.url || '', placeholder: 'ldaps://dc01.company.local:636', required: true, class: 'mono', autocomplete: 'off' });
  const bindDN = h('input', { name: 'username', value: p.bindDN || '', placeholder: 'you@company.local', autocomplete: 'username' });
  const password = h('input', { name: 'password', type: 'password', autocomplete: 'current-password' });
  const baseDN = h('input', { name: 'baseDN', value: p.baseDN || '', placeholder: 'empty = server default', class: 'mono' });
  const startTLS = h('input', { name: 'startTLS', type: 'checkbox', checked: !!p.startTLS });
  const caFile = h('input', { name: 'caFile', value: p.caFile || '', placeholder: '/path/to/company-ca.pem', class: 'mono' });
  const status = h('div');
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Connect');

  const onSubmit = async (ev) => {
    ev.preventDefault();
    submit.disabled = true;
    status.replaceChildren(h('div', { class: 'notice' }, 'Connecting…'));
    try {
      await api.connect({
        url: url.value.trim(), bindDN: bindDN.value.trim(), password: password.value,
        baseDN: baseDN.value.trim(), startTLS: startTLS.checked, caFile: caFile.value.trim(),
      });
      location.hash = '';
      location.reload();
    } catch (err) {
      status.replaceChildren(errorBox(err));
      submit.disabled = false;
    }
  };
  const disconnect = async () => {
    try {
      await api.disconnect();
      location.reload();
    } catch (err) {
      status.replaceChildren(errorBox(err));
    }
  };

  const form = h('form', { class: 'connect', onsubmit: onSubmit },
    h('h1', null, info.connected ? 'Switch server' : 'Connect to a directory'),
    field('Server', url, 'ldaps://host:636, or ldap://host:389 with StartTLS'),
    field(term('bindAccount'), bindDN, 'AD: user@domain or DOMAIN\\user. Empty = anonymous'),
    field('Password', password, 'Used for this connection only; never saved'),
    h('details', { open: !!(p.baseDN || p.startTLS || p.caFile) },
      h('summary', null, 'Advanced'),
      field(term('base'), baseDN),
      h('label', { class: 'check' }, startTLS, 'Encrypt plain ldap:// connections ', h('span', { class: 'term' }, '(', h('code', null, 'StartTLS'), ')')),
      field('CA certificate file', caFile, 'Only if the server certificate is signed by a CA your Mac does not trust')),
    status,
    h('div', { class: 'toolbar' }, ...nodes(submit,
      info.connected ? h('a', { href: '#/browse' }, 'Cancel') : null,
      h('span', { class: 'spacer' }),
      info.connected ? h('button', { type: 'button', onclick: disconnect }, 'Disconnect') : null)));
  el.replaceChildren(h('div', { class: 'page' }, form));
  (url.value ? (bindDN.value ? password : bindDN) : url).focus();
}
