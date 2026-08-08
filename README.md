<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-ldap/brand/main/social/go-ruby-ldap-ldap.png" alt="go-ruby-ldap/ldap" width="720"></p>

# ldap — go-ruby-ldap

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-ldap.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo), MRI-faithful reimplementation of the Ruby
[`net-ldap`](https://github.com/ruby-ldap/ruby-net-ldap) gem's `Net::LDAP`
client surface** — the ergonomics and result/error model of the gem's
connection object (`bind`, `search`, `add`, `modify`, `delete`, `rename`,
`Net::LDAP::Filter`, `Net::LDAP::Entry`, `get_operation_result`) layered over
the official pure-Go LDAP client.

It does **not** reimplement the LDAP protocol. It consumes
[`github.com/go-ldap/ldap/v3`](https://pkg.go.dev/github.com/go-ldap/ldap/v3) as
its transport and maps the gem's API onto it, so a static, CGO=0 binary talks to
a real directory (OpenLDAP, Active Directory, 389 Directory Server, …).

It is the LDAP backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-etcd](https://github.com/go-ruby-etcd/etcd) and
[go-ruby-redis](https://github.com/go-ruby-redis/redis).

> **Transport is a host seam.** A [`Client`](client.go) drives an injected
> transport whose method set is satisfied directly by `*ldap.Conn` (no adapter).
> This makes every method's request-building and response-mapping logic testable
> against a **deterministic in-memory transport** — no external directory, no cgo
> — so the suite holds **100% coverage on every arch under qemu**. A separate
> [live suite](live/) drives an in-process, pure-Go LDAP server for real
> round-trip validation on native lanes.

## Features

- **Bind** — `Bind` (simple / anonymous, from the configured credentials) and
  `BindWith` (per-call credentials); a failed bind records
  [`ErrInvalidCredentials`](errors.go) rather than raising.
- **Search** — `Search` and `SearchEach` (the block form) over `ScopeBase`,
  `ScopeSingleLevel` and `ScopeSubtree`, with attribute selection, size / time
  limits and a base falling back to the client's configured base.
- **Entry** — a case-insensitive `Entry` mirroring `Net::LDAP::Entry`: `DN`,
  `Get`, `First`, `AttributeNames`.
- **Filter** — a `Filter` builder mirroring `Net::LDAP::Filter`: `Eq`,
  `Present`, `Ge`, `Le`, `Approx`, `Contains` / `Begins` / `Ends` (substrings),
  `And` / `Or` / `Not`, and `Construct` (RFC 4515 string parsing), with RFC 4515
  value escaping.
- **Modify** — `Add`, `Modify` (`ModAdd` / `ModReplace` / `ModDelete`
  operations), `ReplaceAttribute` / `AddAttribute` / `DeleteAttribute`,
  `Delete`, `Rename` (modify RDN, with an optional new superior) and `Compare`.
- **Result** — an `OperationResult` mirroring `#get_operation_result` (code,
  name, message, matched DN), updated by every operation.
- **Errors** — a net-ldap-style error tree (`Error` + one sentinel per LDAP
  result code, plus synthetic network / filter-syntax codes) matchable with
  `errors.Is`.

## Usage

```go
c, err := ldap.New(ldap.Config{
	Host:     "127.0.0.1",
	Port:     389,
	Base:     "dc=example,dc=com",
	Method:   "simple",
	Username: "cn=admin,dc=example,dc=com",
	Password: "secret",
})
if err != nil {
	log.Fatal(err)
}
defer c.Close()

if err := c.Bind(); err != nil {
	log.Fatalf("bind: %v (%+v)", err, c.OperationResult())
}

res, _ := c.Search(&ldap.SearchRequest{
	Scope:  ldap.ScopeSubtree,
	Filter: ldap.And(ldap.Eq("objectClass", "person"), ldap.Begins("cn", "al")),
})
for _, e := range res.Entries {
	fmt.Println(e.DN(), e.First("mail"))
}
```

## Ruby mapping

| net-ldap gem                              | go-ruby-ldap/ldap                                    |
| ----------------------------------------- | ---------------------------------------------------- |
| `Net::LDAP.new(host:, port:, base:, ...)` | `ldap.New(ldap.Config{...})`                         |
| `ldap.bind`                               | `c.Bind()`                                           |
| `ldap.search(filter:, base:) { \|e\| }`   | `c.Search(&ldap.SearchRequest{...})` / `SearchEach`  |
| `ldap.add(dn:, attributes:)`              | `c.Add(dn, attrs)`                                   |
| `ldap.modify(dn:, operations:)`           | `c.Modify(dn, ops)`                                  |
| `ldap.delete(dn:)`                        | `c.Delete(dn)`                                       |
| `ldap.rename(olddn:, newrdn:)`            | `c.Rename(olddn, newrdn, true, "")`                  |
| `Net::LDAP::Filter.eq("cn", "a")`         | `ldap.Eq("cn", "a")`                                 |
| `Net::LDAP::Filter.construct(str)`        | `ldap.Construct(str)`                                |
| `ldap.get_operation_result`               | `c.OperationResult()`                                |

## Tests & coverage

The default suite runs with `-race` and holds **100% statement coverage** on all
three host OSes and the six supported 64-bit architectures (amd64, arm64,
riscv64, loong64, ppc64le and big-endian s390x), driving the full client logic
against a deterministic in-memory transport with no external directory:

```sh
go test -race -cover ./...
```

The [`live/`](live/) nested module validates real round-trip behaviour against
an in-process, pure-Go LDAP server (native-only; kept out of the main module so
its server dependency never enters this go.mod):

```sh
cd live && go test ./...
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026, the go-ruby-ldap/ldap
authors.
