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
| `-container` | allow a non-loopback `-listen` inside a container; set by the Docker image |

### In Docker

```sh
make docker-run                          # http://127.0.0.1:8389, restarts with Docker
make docker-run CA_FILE=~/company-ca.pem # trust a company CA
make docker-logs / make docker-stop
```

The container doesn't see the CA certificates in your Mac's Keychain. If the
DC uses a company CA, pass `CA_FILE`; the connect page then fills in
`/certs/ca.pem` for you. Saved connection settings live in the
`ldap-console-config` volume.

`make docker-run` publishes the port on `127.0.0.1` only. If you run the
image yourself, keep the `127.0.0.1:` in `-p 127.0.0.1:8389:8389`. Without it,
anyone on your network can browse the directory as you. Inside the image the
console runs with `-container`, which lets it listen on `0.0.0.0` (so it can
receive Docker's forwarded traffic) and leaves exposure to the `-p` setting.

To try it without a domain controller, run `go run ./cmd/ldap-demo` and follow the command it prints.

## What it shows

- **Browse**: a lazily loaded DIT tree, plus each entry's attributes with AD values decoded: `objectSid`, `objectGUID`, FILETIME timestamps, `userAccountControl` flags and `groupType`.
- **Member of** (users, computers, groups): every group the account belongs to, marked *direct*, *nested* (with the chain of groups that grants it), or *primary* (AD `primaryGroupID`, which `memberOf` never lists).
- **Members** (groups): direct members, or with *Include nested* the members of sub-groups too, each with its path. Disabled accounts are flagged.
- **People → groups**: paste up to 200 names (logins, `DOMAIN\login`, UPNs or e-mail addresses, exact CN or display name, or DNs) and see every group each person is in, side by side: one row per group, one column per person, each cell *direct*, *nested* (hover for the chain) or *primary*. Groups everyone shares are highlighted and can be filtered to. Names that match nothing, or several accounts, are listed separately; for an ambiguous one you pick the right account. Export as a matrix or a long list (CSV). Tick groups to hand them to the filter builder.
- **Filter builder**: composes LDAP login settings from a few choices: account type (AD users, inetOrgPerson, posixAccount), login and e-mail attribute, which groups may log in (optionally counting nested members through AD's `LDAP_MATCHING_RULE_IN_CHAIN`), which groups are admins, excluding disabled AD accounts, and requiring an e-mail address. It writes them in each application's own form: Generic (`{username}` / `{dn}` user and group filters), Gitea (`%[1]s`, with a literal `%` doubled for its `fmt.Sprintf`; Admin Filter) and Open WebUI (username attribute plus `LDAP_SEARCH_FILTERS`). Group DNs are escaped per RFC 4515. *List matching accounts* runs the filter to show who could log in; *Try in Login test* opens the login test with the settings filled in.
- **Why (not)?**: pick a person and a set of conditions, and see whether that account matches and why not. Every part of the conditions is checked against the account by the server itself, so AD's matching rules count exactly as a real search would. Each part gets a plain-English sentence and the account's actual values, and the parts that block a match are listed first. Two cases get called out:
  - The account is outside *Where to search*.
  - A plain `memberOf` test fails although the person is in the group through a sub-group. The console then gives the `LDAP_MATCHING_RULE_IN_CHAIN` condition that counts sub-groups.

  Placeholders such as `{username}` / `%[1]s` are filled with what the person would type, so a login typed in the wrong form (email instead of login name) shows up too. It's available in three places:
  - Filter builder: *Why can or can't someone log in?*
  - Search: *Why is someone (not) in the results?*
  - Login test: it runs by itself when the user isn't found, and is offered on the admin and restricted steps.
- **Groups**: every group with its direct member count (on AD, "100+" above 100), type and OU. You can filter it and export it to CSV.
- **Login test**: checks an application's LDAP login settings before you save them there. It replays the login for one user step by step: find the user with the user filter (exactly one must match), optionally sign in with their password, then find their groups. Modes: *Generic* (`{username}` / `{dn}` placeholders; `%s` and `%[1]s` also work), *Gitea* (filled with `%[1]s` exactly as Gitea does; user, admin and restricted filters, email attribute, group verification), and *Open WebUI* (username attribute plus search filters, mail attribute, `memberOf` groups; like Open WebUI, several matches log in as the first). The password is used for one bind on a separate connection and never stored. AD's bind error codes are spelled out (wrong password, disabled, locked, expired…).
- **Search**: raw LDAP filters with presets (disabled users, locked out, password never expires, empty groups, …). Results export to CSV.

Labels are written for people who don't know LDAP: plain English first, with
the LDAP or application term after it in parentheses, e.g. *Where to search
(`Base DN`)* or *Which accounts can log in (`User Filter`)*, so they can still
be matched against an application's settings page. The wording lives in one
glossary, `web/static/js/terms.js`.

## Behaviour on large directories

- Every search uses paged results (RFC 2696), so AD's 1000-entry cap doesn't silently truncate lists.
- Big multi-valued attributes (`member;range=0-1499`) are fetched in full.
- Searches stop at size limits (tree level 2000, search ≤ 10000, membership walk 20000). When a limit is hit the UI says the list was truncated rather than showing a partial list as if it were complete.
- Nested-group walks detect cycles and stop at 32 levels deep.

## Security

- Read-only towards the directory. The only POST endpoints are connect, disconnect and login test (it carries a password), and they accept a request only when all three checks pass: the `Origin` is the console itself, the body is JSON, and the request carries a token generated at each launch. A malicious page open in the same browser therefore can't point the console at a server it controls.
- The UI listens only on loopback (in Docker: published on `127.0.0.1` only), and requests are refused if their `Host` header isn't a local name (this blocks DNS-rebinding attacks).
- Strict CSP. Directory values are only rendered as text, never as HTML.
- User input is escaped before it goes into filters. Raw filters from the Search view are compiled and checked before they're sent.

## Development

```sh
make demo      # console + built-in fake AD, no DC needed
make install   # ldap-console into $(go env GOPATH)/bin
make test lint cover
```

Tests run against an in-process fake LDAP server (`internal/ldaptest`) that
emulates paging, ranged retrieval, AD-style bind/memberOf, `objectCategory`
short names, and AD's bitwise (`1.2.840.113556.1.4.803`/`804`) and in-chain
(`1.2.840.113556.1.4.1941`) matching rules, so the filters the builder writes
run in tests and in `make demo`.

## Roadmap

Phase 2, writes: editing attributes and adding or removing group members. These
will be behind `--allow-write`, and each change will need confirmation against
an LDIF-style diff.
