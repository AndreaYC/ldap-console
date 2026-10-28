# ldap-console

A local, read-only web UI for browsing LDAP / Active Directory and seeing how
accounts and groups relate. It's a single Go binary with the UI embedded. No
Node build step.

## Run

```sh
make install
ldap-console        # → http://127.0.0.1:8389
```

With no `-url`, the page asks for the server, bind account and password. The
server, account, base DN, StartTLS setting and CA file are remembered in
`~/Library/Application Support/ldap-console/profile.json` (or `~/.config/…`
on Linux). The password is never saved. Use **Switch** in the header to
change servers.

You can also connect at launch, skipping the page:

```sh
export LDAP_BIND_PASSWORD='…'          # or leave unset to be prompted
ldap-console -url ldaps://dc01.corp.local:636 -bind-dn svc-ldap@corp.local
```

| Flag / env | Purpose |
|---|---|
| `-url` / `LDAP_URL` | `ldap://host:389` or `ldaps://host:636`; empty = choose it in the UI |
| `-bind-dn` / `LDAP_BIND_DN` | bind identity; empty = anonymous (AD refuses this) |
| `LDAP_BIND_PASSWORD` | password. Never a flag, so it can't leak into `ps` or shell history |
| `-base-dn` / `LDAP_BASE_DN` | defaults to the server's `defaultNamingContext` |
| `-start-tls`, `-ca-file`, `-insecure-skip-verify` | TLS options; certificates are verified by default |
| `-allow-cleartext` | permit a password bind over plain `ldap://` to a non-loopback host (refused otherwise) |

`-insecure-skip-verify`, `-allow-cleartext`, `-page-size` and `-timeout` also apply to connections made from the page. The page itself cannot turn on the two risky ones.
| `-listen` | UI address; must be loopback (the UI has no login and acts as the bind DN) |

To try it without a domain controller, run `go run ./cmd/ldap-demo` and follow the command it prints.

## What it shows

- **Browse**: a lazily loaded DIT tree, plus each entry's attributes with AD values decoded: `objectSid`, `objectGUID`, FILETIME timestamps, `userAccountControl` flags and `groupType`.
- **Member of** (users, computers, groups): every group the account belongs to, marked *direct*, *nested* (with the chain of groups that grants it), or *primary* (AD `primaryGroupID`, which `memberOf` never lists).
- **Members** (groups): direct members, or with *Include nested* the members of sub-groups too, each with its path. Disabled accounts are flagged.
- **Groups**: every group with its type and OU. You can filter it and export it to CSV.
- **Search**: raw LDAP filters with presets (disabled users, locked out, password never expires, empty groups, …). Results export to CSV.

## Behaviour on large directories

- Every search uses paged results (RFC 2696), so AD's 1000-entry cap doesn't silently truncate lists.
- Big multi-valued attributes (`member;range=0-1499`) are fetched in full.
- Searches stop at size limits (tree level 2000, search ≤ 10000, membership walk 20000). When a limit is hit the UI says the list was truncated rather than showing a partial list as if it were complete.
- Nested-group walks detect cycles and stop at 32 levels deep.

## Security

- Read-only towards the directory. The only POST endpoints are connect and disconnect, and they accept a request only when all three checks pass: the `Origin` is the console itself, the body is JSON, and the request carries a token generated at each launch. A malicious page open in the same browser therefore can't point the console at a server it controls.
- The UI listens only on loopback, and requests are refused if their `Host` header isn't a local name (this blocks DNS-rebinding attacks).
- Strict CSP. Directory values are only rendered as text, never as HTML.
- User input is escaped before it goes into filters. Raw filters from the Search view are compiled and checked before they're sent.

## Development

```sh
make demo      # console + built-in fake AD, no DC needed
make install   # ldap-console into $(go env GOPATH)/bin
make test lint cover
```

Tests run against an in-process fake LDAP server (`internal/ldaptest`) that
emulates paging, ranged retrieval and AD-style bind/memberOf.

**Gap:** the fake doesn't emulate AD extensible matching rules (for example the
bitwise `userAccountControl:1.2.840.113556.1.4.803:=2` used by some search
presets). Those filters pass through unchanged to a real DC, but the tests
don't cover them.

## Roadmap

Phase 2, writes: editing attributes and adding or removing group members. These
will be behind `--allow-write`, and each change will need confirmation against
an LDIF-style diff.
