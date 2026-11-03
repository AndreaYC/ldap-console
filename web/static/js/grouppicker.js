import { api } from './api.js';
import { h, rdnValue } from './dom.js';

let groupsList; // one directory-wide group list per page load

// allGroups resolves to every group (name and DN); [] if it can't be read.
export function allGroups() {
  groupsList ??= api.groups().then((r) => r.items).catch(() => []);
  return groupsList;
}

let pickerCount = 0;

// groupPicker edits list, an array of group DNs, as removable chips with a
// type-ahead input. A group is picked by name or DN, or pasted as a DN.
// onChange runs after every change.
export function groupPicker(list, onChange, { placeholder = 'Add a group…', tone = '' } = {}) {
  const id = 'group-options-' + (++pickerCount);
  const options = h('datalist', { id });
  allGroups().then((gs) => options.replaceChildren(...gs.map((g) => h('option', { value: g.name }, g.dn))));
  const chips = h('div', { class: 'chips' });
  const input = h('input', { list: id, placeholder, autocomplete: 'off', 'aria-label': 'Add a group', class: 'chip-input' });
  const msg = h('div', { class: 'hint error-text', 'aria-live': 'polite' });

  const draw = () => {
    chips.replaceChildren(...list.map((dn, i) => h('span', { class: 'chip ' + tone, title: dn },
      rdnValue(dn),
      h('button', { type: 'button', class: 'chip-x', 'aria-label': 'Remove ' + rdnValue(dn),
        onclick: () => { list.splice(i, 1); draw(); onChange(); } }, '×'))), input);
  };

  // Enter fires both keydown and change; the second call finds the value
  // already taken and returns.
  let pending = '';
  const add = async () => {
    const v = input.value.trim();
    if (!v || v === pending) return;
    msg.textContent = '';
    pending = v;
    const groups = await allGroups();
    pending = '';
    const lower = v.toLowerCase();
    let dn = groups.find((g) => g.dn.toLowerCase() === lower)?.dn;
    if (!dn) {
      const byName = groups.filter((g) => g.name.toLowerCase() === lower);
      if (byName.length > 1) { msg.textContent = `${byName.length} groups are called ${v}; paste the full path (DN) of the one you mean`; return; }
      dn = byName[0]?.dn;
    }
    if (!dn && /^[A-Za-z][\w-]*=/.test(v)) dn = v; // a DN outside the listed groups
    if (!dn) { msg.textContent = `No group called ${v}`; return; }
    if (!list.some((d) => d.toLowerCase() === dn.toLowerCase())) list.push(dn);
    input.value = '';
    draw();
    onChange();
    input.focus();
  };
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
  input.addEventListener('change', add);
  draw();
  return h('div', { class: 'picker' }, options, chips, msg);
}
