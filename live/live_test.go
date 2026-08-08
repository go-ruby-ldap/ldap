// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package live drives the go-ruby-ldap/ldap Client against a real, in-process
// LDAP server built with the pure-Go github.com/glauth/ldap server package. It
// lives in its own nested module so the server dependency never enters the main
// module's go.mod: the main module's default suite reaches 100% coverage on
// every arch under qemu against a deterministic in-memory transport, while this
// suite validates real round-trip behaviour on native lanes. Run it with:
//
//	cd live && go test ./...
//
// It complements the deterministic suite by exercising genuine LDAP semantics:
// a simple bind (and its rejection), a real filter engine evaluating the Filter
// builder's output over a directory, and a delete verified by a follow-up
// search. Add / Modify / Rename / Compare are exercised as protocol round trips
// (the server acknowledges them) so the client's request encoding and response
// decoding are validated end to end.
package live

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	server "github.com/glauth/ldap"
	client "github.com/go-ruby-ldap/ldap"
)

// dir is a tiny in-memory directory backing the in-process server. It is not a
// full DSA: it applies the bind check, real filter-based search and delete, and
// acknowledges the remaining operations so their round trips can be validated.
type dir struct {
	mu      sync.Mutex
	entries map[string]map[string][]string
}

const (
	adminDN = "cn=admin,dc=example,dc=com"
	adminPW = "secret"
)

func (d *dir) Bind(bindDN, pw string, conn net.Conn) (server.LDAPResultCode, error) {
	if bindDN == adminDN && pw == adminPW {
		return server.LDAPResultSuccess, nil
	}
	return server.LDAPResultInvalidCredentials, nil
}

func (d *dir) Search(boundDN string, req server.SearchRequest, conn net.Conn) (server.ServerSearchResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	packet, err := server.CompileFilter(req.Filter)
	if err != nil {
		return server.ServerSearchResult{ResultCode: server.LDAPResultOperationsError}, err
	}
	base := strings.ToLower(req.BaseDN)
	var out []*server.Entry
	for dn, attrs := range d.entries {
		if !inScope(strings.ToLower(dn), base, req.Scope) {
			continue
		}
		e := &server.Entry{DN: dn}
		for name, vals := range attrs {
			e.Attributes = append(e.Attributes, &server.EntryAttribute{Name: name, Values: vals})
		}
		ok, _ := server.ServerApplyFilter(packet, e)
		if ok {
			out = append(out, e)
		}
	}
	return server.ServerSearchResult{Entries: out, ResultCode: server.LDAPResultSuccess}, nil
}

func (d *dir) Delete(boundDN, deleteDN string, conn net.Conn) (server.LDAPResultCode, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.entries[deleteDN]; !ok {
		return server.LDAPResultNoSuchObject, nil
	}
	delete(d.entries, deleteDN)
	return server.LDAPResultSuccess, nil
}

func (d *dir) Add(boundDN string, req server.AddRequest, conn net.Conn) (server.LDAPResultCode, error) {
	return server.LDAPResultSuccess, nil
}

func (d *dir) Modify(boundDN string, req server.ModifyRequest, conn net.Conn) (server.LDAPResultCode, error) {
	return server.LDAPResultSuccess, nil
}

func (d *dir) ModifyDN(boundDN string, req server.ModifyDNRequest, conn net.Conn) (server.LDAPResultCode, error) {
	return server.LDAPResultSuccess, nil
}

func (d *dir) Compare(boundDN string, req server.CompareRequest, conn net.Conn) (server.LDAPResultCode, error) {
	return server.LDAPResultCompareTrue, nil
}

// inScope reports whether dn falls within base at the given LDAP scope (all
// arguments lower-cased).
func inScope(dn, base string, scope int) bool {
	switch scope {
	case server.ScopeBaseObject:
		return dn == base
	case server.ScopeSingleLevel:
		if !strings.HasSuffix(dn, ","+base) {
			return false
		}
		return !strings.Contains(strings.TrimSuffix(dn, ","+base), ",")
	default:
		return dn == base || strings.HasSuffix(dn, ","+base)
	}
}

// startServer boots the in-process LDAP server on an ephemeral loopback port and
// returns its host:port. The listener and server are torn down in a t.Cleanup.
func startServer(t *testing.T) string {
	t.Helper()
	d := &dir{entries: map[string]map[string][]string{
		"dc=example,dc=com":                    {"objectClass": {"domain"}, "dc": {"example"}},
		"ou=people,dc=example,dc=com":          {"objectClass": {"organizationalUnit"}, "ou": {"people"}},
		"cn=alice,ou=people,dc=example,dc=com": {"objectClass": {"person"}, "cn": {"alice"}, "mail": {"alice@example.com"}},
		"cn=bob,ou=people,dc=example,dc=com":   {"objectClass": {"person"}, "cn": {"bob"}, "mail": {"bob@example.com"}},
		"cn=carol,ou=people,dc=example,dc=com": {"objectClass": {"person"}, "cn": {"carol"}, "mail": {"carol@example.com"}},
	}}
	s := server.NewServer()
	s.BindFunc("", d)
	s.SearchFunc("", d)
	s.AddFunc("", d)
	s.ModifyFunc("", d)
	s.DeleteFunc("", d)
	s.ModifyDNFunc("", d)
	s.CompareFunc("", d)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	// Give the accept loop a moment to be ready.
	time.Sleep(50 * time.Millisecond)
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) *client.Client {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Config{
		Host: host, Port: p, Base: "dc=example,dc=com",
		Method: "simple", Username: adminDN, Password: adminPW,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestLiveBindSearchDelete(t *testing.T) {
	addr := startServer(t)
	c := dial(t, addr)

	// Simple bind with the right credentials.
	if err := c.Bind(); err != nil {
		t.Fatalf("bind: %v (%+v)", err, c.OperationResult())
	}

	// Real filter engine: (&(objectClass=person)(cn=al*)) matches only alice.
	res, err := c.Search(&client.SearchRequest{
		Scope:  client.ScopeSubtree,
		Filter: client.And(client.Eq("objectClass", "person"), client.Begins("cn", "al")),
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].First("cn") != "alice" {
		t.Fatalf("filtered search: %+v", res.Entries)
	}

	// Presence filter over the people subtree: all three persons.
	res, _ = c.Search(&client.SearchRequest{
		Base:   "ou=people,dc=example,dc=com",
		Scope:  client.ScopeSingleLevel,
		Filter: client.Present("mail"),
	})
	if len(res.Entries) != 3 {
		t.Fatalf("present search: %d", len(res.Entries))
	}

	// Delete carol, then confirm she is gone via a follow-up search.
	if err := c.Delete("cn=carol,ou=people,dc=example,dc=com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	res, _ = c.Search(&client.SearchRequest{Scope: client.ScopeSubtree, Filter: client.Eq("cn", "carol")})
	if len(res.Entries) != 0 {
		t.Fatalf("carol should be deleted: %+v", res.Entries)
	}

	// Deleting again reports no-such-object.
	if err := c.Delete("cn=carol,ou=people,dc=example,dc=com"); err == nil {
		t.Fatal("expected no-such-object on second delete")
	}
}

func TestLiveBindFailure(t *testing.T) {
	addr := startServer(t)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	fmt.Sscanf(port, "%d", &p)
	c, err := client.New(client.Config{Host: host, Port: p, Method: "simple", Username: adminDN, Password: "wrong"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	if err := c.Bind(); err == nil {
		t.Fatal("expected bind failure")
	}
	if c.OperationResult().Code == 0 {
		t.Fatalf("expected non-zero result code, got %+v", c.OperationResult())
	}
}

func TestLiveMutationRoundTrips(t *testing.T) {
	addr := startServer(t)
	c := dial(t, addr)
	if err := c.Bind(); err != nil {
		t.Fatal(err)
	}
	// Add / Modify / Rename / Compare are acknowledged by the server, so the
	// client's request encoding and response decoding round-trip cleanly.
	if err := c.Add("cn=dave,ou=people,dc=example,dc=com", map[string][]string{"cn": {"dave"}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := c.Modify("cn=alice,ou=people,dc=example,dc=com", []client.ModifyOp{
		{Type: client.ModReplace, Attr: "mail", Values: []string{"alice@corp.example.com"}},
	}); err != nil {
		t.Fatalf("modify: %v", err)
	}
	if err := c.Rename("cn=bob,ou=people,dc=example,dc=com", "cn=bobby", true, ""); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if ok, err := c.Compare("cn=alice,ou=people,dc=example,dc=com", "cn", "alice"); err != nil || !ok {
		t.Fatalf("compare: ok=%v err=%v", ok, err)
	}
}
