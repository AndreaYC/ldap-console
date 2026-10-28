import { api } from './api.js';
import { h, kindBadge, rdnValue, splitDN } from './dom.js';

// Tree is a lazily expanded view of the DIT. Nodes are keyed by lowercased DN.
export class Tree {
  constructor(roots, onSelect) {
    this.onSelect = onSelect;
    this.nodes = new Map();
    this.selected = null;
    this.el = h('div', { class: 'tree' });
    const ul = h('ul');
    for (const dn of roots) ul.append(this.#node({ dn, name: dn, kind: 'container' }));
    this.el.append(ul);
  }

  #node(obj) {
    const caret = h('span', { class: 'caret' }, obj.kind === 'container' ? '▶' : '');
    const row = h('div', { class: 'node', title: obj.dn },
      caret, kindBadge(obj.kind), h('span', { class: 'name' }, obj.name || rdnValue(obj.dn)),
      obj.disabled ? h('span', { class: 'tag disabled' }, 'disabled') : null);
    const li = h('li', null, row);
    const state = { obj, li, row, caret, children: null, open: false };
    this.nodes.set(obj.dn.toLowerCase(), state);

    caret.addEventListener('click', (ev) => { ev.stopPropagation(); this.toggle(state); });
    row.addEventListener('click', () => this.onSelect(obj.dn));
    row.addEventListener('dblclick', () => this.toggle(state));
    return li;
  }

  async toggle(state) {
    if (state.loading) return;
    if (state.open) {
      state.children?.remove();
      state.children = null;
      state.open = false;
      state.caret.textContent = '▶';
      return;
    }
    await this.expand(state);
  }

  // expand loads children once; concurrent callers share the same load.
  expand(state) {
    if (!state.loading) state.loading = this.#load(state).finally(() => { state.loading = null; });
    return state.loading;
  }

  async #load(state) {
    if (state.open) return;
    state.open = true;
    state.caret.textContent = '…';
    try {
      const res = await api.children(state.obj.dn);
      const ul = h('ul');
      for (const child of res.items) ul.append(this.#node(child));
      if (res.truncated) ul.append(h('li', { class: 'notice' }, 'Showing first entries only — use Search for the rest'));
      state.children = ul;
      state.li.append(ul);
      state.caret.textContent = res.items.length ? '▼' : '';
    } catch (err) {
      state.open = false;
      state.caret.textContent = '!';
      state.caret.title = err.message;
    }
  }

  // reveal expands ancestors of dn that lie under a root, then selects it.
  async reveal(dn) {
    const parts = splitDN(dn);
    for (let i = parts.length - 1; i >= 1; i--) {
      const ancestor = this.nodes.get(parts.slice(i).join(',').toLowerCase());
      if (ancestor) await this.expand(ancestor);
    }
    this.select(dn);
  }

  select(dn) {
    this.selected?.row.classList.remove('sel');
    this.selected = this.nodes.get(dn.toLowerCase()) || null;
    if (this.selected) {
      this.selected.row.classList.add('sel');
      this.selected.row.scrollIntoView({ block: 'nearest' });
    }
  }
}
