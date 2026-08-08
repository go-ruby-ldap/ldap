// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

// tlsConfigInsecure is a throwaway TLS config used to drive New's TLS dial
// branch; the dial fails to connect before any handshake, so its contents do
// not matter.
var tlsConfigInsecure = tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only, never handshakes

// --- client.go: New / configURL ---

// acceptLoop starts a bare TCP listener that accepts and immediately drops every
// connection. DialURL for a plaintext ldap:// URL only opens the TCP connection
// (the LDAP bind is lazy), so this is enough to drive New's success path without
// a real directory. It returns the listener address and a stop func.
func acceptLoop(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestNewSuccessViaURL(t *testing.T) {
	addr, stop := acceptLoop(t)
	defer stop()
	c, err := New(Config{URL: "ldap://" + addr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Base() != "" {
		t.Fatalf("base: %q", c.Base())
	}
	_ = c.Close()
}

func TestNewSuccessViaHostPort(t *testing.T) {
	addr, stop := acceptLoop(t)
	defer stop()
	host, port, _ := net.SplitHostPort(addr)
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Host: host, Port: p, Base: "dc=example,dc=com", Method: "anonymous"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Base() != "dc=example,dc=com" {
		t.Fatalf("base: %q", c.Base())
	}
	// A fresh client reports a Success operation result before any operation.
	if r := c.OperationResult(); r.Name != "Success" {
		t.Fatalf("fresh result: %+v", r)
	}
	_ = c.Close()
}

func TestNewConnectionRefused(t *testing.T) {
	// Port 1 on loopback is not listening: DialURL fails, mapped to a network error.
	_, err := New(Config{Host: "127.0.0.1", Port: 1})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected network error, got %v", err)
	}
}

func TestNewTLSDialFailure(t *testing.T) {
	// TLS to a non-listening port exercises the TLS branch of both configURL
	// (ldaps scheme, default port 636) and New (DialWithTLSConfig), then fails to
	// connect and maps to a network error.
	_, err := New(Config{Host: "127.0.0.1", TLS: &tlsConfigInsecure})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected network error, got %v", err)
	}
}

func TestNewMalformedURL(t *testing.T) {
	_, err := New(Config{URL: "ldap://\x00bad"})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected network error for malformed URL, got %v", err)
	}
}

func TestConfigURL(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, "ldap://127.0.0.1:389"}, // all defaults
		{Config{Host: "ldap.example.com", Port: 1389}, "ldap://ldap.example.com:1389"},
		{Config{TLS: &tlsConfigInsecure}, "ldaps://127.0.0.1:636"},                // TLS default port
		{Config{TLS: &tlsConfigInsecure, Port: 10636}, "ldaps://127.0.0.1:10636"}, // explicit TLS port
		{Config{URL: "ldap://host:389"}, "ldap://host:389"},                       // explicit URL
	}
	for _, tc := range cases {
		got, err := configURL(tc.cfg)
		if err != nil {
			t.Fatalf("configURL(%+v): %v", tc.cfg, err)
		}
		if got != tc.want {
			t.Fatalf("configURL(%+v) = %q, want %q", tc.cfg, got, tc.want)
		}
	}
	if _, err := configURL(Config{URL: "ldap://\x00bad"}); !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected network error for malformed URL")
	}
}

// --- client.go: Bind / record / OperationResult ---

func TestBindSimpleSuccessAndFailure(t *testing.T) {
	f := newFakeConn()
	f.validUser, f.validPassword = "cn=admin", "secret"
	c := newWithTransport(f, Config{Method: "simple", Username: "cn=admin", Password: "secret"})

	if err := c.Bind(); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if r := c.OperationResult(); r.Code != 0 || r.Name != "Success" {
		t.Fatalf("result: %+v", r)
	}

	bad := newWithTransport(f, Config{Username: "cn=admin", Password: "wrong"})
	err := bad.Bind()
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if r := bad.OperationResult(); r.Code != goldap.LDAPResultInvalidCredentials || r.Name != "InvalidCredentials" {
		t.Fatalf("result: %+v", r)
	}
}

func TestBindAnonymous(t *testing.T) {
	f := newFakeConn()
	c := newWithTransport(f, Config{Method: "ANONYMOUS", Username: "cn=probe"})
	if err := c.Bind(); err != nil {
		t.Fatalf("anon bind: %v", err)
	}
	f.errBind = strErr("boom")
	if err := c.Bind(); err == nil {
		t.Fatal("expected anon bind error")
	}
}

func TestBindWith(t *testing.T) {
	f := newFakeConn()
	f.validUser, f.validPassword = "u", "p"
	c := newWithTransport(f, Config{})
	if err := c.BindWith("u", "p"); err != nil {
		t.Fatalf("bindwith: %v", err)
	}
	if err := c.BindWith("u", "x"); err == nil {
		t.Fatal("expected failure")
	}
}

func TestRecordMatchedDN(t *testing.T) {
	f := newFakeConn()
	c := newWithTransport(f, Config{})
	// Delete of a missing DN returns a NoSuchObject *ldap.Error carrying a
	// matched DN, so record captures it.
	err := c.Delete("cn=ghost,dc=x")
	if !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("expected no such object, got %v", err)
	}
	if r := c.OperationResult(); r.MatchedDN != "cn=ghost,dc=x" || r.Name != "NoSuchObject" {
		t.Fatalf("result: %+v", r)
	}
}

func TestCloseError(t *testing.T) {
	f := newFakeConn()
	f.errClose = strErr("close boom")
	c := newWithTransport(f, Config{})
	if err := c.Close(); err == nil {
		t.Fatal("expected close error")
	}
}

// --- errors.go ---

func TestErrorFormatting(t *testing.T) {
	if got := ErrNoSuchObject.Error(); got != "ldap: NoSuchObject (32)" {
		t.Fatalf("no-message format: %q", got)
	}
	e := &Error{Code: 32, Name: "NoSuchObject", Message: "nope"}
	if got := e.Error(); got != "ldap: NoSuchObject (32): nope" {
		t.Fatalf("message format: %q", got)
	}
}

func TestMapError(t *testing.T) {
	if mapError(nil) != nil {
		t.Fatal("nil should map to nil")
	}
	if got := mapError(ErrNoSuchObject); got != ErrNoSuchObject {
		t.Fatalf("already-Error: %v", got)
	}
	// A plain (non-ldap) error maps to a network error.
	e := mapError(strErr("dial tcp: refused")).(*Error)
	if e.Code != CodeNetwork || e.Name != "Network" {
		t.Fatalf("network map: %+v", e)
	}
	// An *ldap.Error with Err set uses the wrapped message.
	le := mapError(&goldap.Error{ResultCode: goldap.LDAPResultBusy, Err: strErr("try later")}).(*Error)
	if le.Code != goldap.LDAPResultBusy || le.Name != "Busy" || le.Message != "try later" {
		t.Fatalf("ldap map: %+v", le)
	}
}

func TestNameForAndCleanMessage(t *testing.T) {
	// In codeName.
	if nameFor(goldap.LDAPResultNoSuchObject) != "NoSuchObject" {
		t.Fatal("codeName miss")
	}
	// Not in codeName but in go-ldap's description map (Referral, code 10).
	if got := nameFor(goldap.LDAPResultReferral); got != "Referral" {
		t.Fatalf("referral name: %q", got)
	}
	// In neither map.
	if got := nameFor(9999); got != "Error" {
		t.Fatalf("unknown name: %q", got)
	}
	// cleanMessage: no wrapped Err, code known -> description.
	m := mapError(&goldap.Error{ResultCode: goldap.LDAPResultNoSuchObject}).(*Error)
	if m.Message != "No Such Object" {
		t.Fatalf("desc message: %q", m.Message)
	}
	// cleanMessage: no wrapped Err, code unknown -> empty message.
	m2 := mapError(&goldap.Error{ResultCode: 9999}).(*Error)
	if m2.Message != "" {
		t.Fatalf("empty message expected, got %q", m2.Message)
	}
}

func TestErrorIsAndUnwrap(t *testing.T) {
	orig := &goldap.Error{ResultCode: goldap.LDAPResultNoSuchObject, Err: strErr("x")}
	mapped := mapError(orig)
	if !errors.Is(mapped, ErrNoSuchObject) {
		t.Fatal("should match ErrNoSuchObject")
	}
	if errors.Is(mapped, ErrInvalidCredentials) {
		t.Fatal("should not match ErrInvalidCredentials")
	}
	if ErrNoSuchObject.Is(errors.New("plain")) {
		t.Fatal("non-Error target should not match")
	}
	if errors.Unwrap(mapped) == nil {
		t.Fatal("mapped error should unwrap to cause")
	}
	if errors.Unwrap(ErrNoSuchObject) != nil {
		t.Fatal("sentinel should unwrap to nil")
	}
}

// --- search.go ---

func seedDirectory(f *fakeConn) {
	f.entries["dc=example,dc=com"] = map[string][]string{"objectClass": {"domain"}, "dc": {"example"}}
	f.entries["ou=people,dc=example,dc=com"] = map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}}
	f.entries["cn=alice,ou=people,dc=example,dc=com"] = map[string][]string{"cn": {"alice"}, "mail": {"alice@example.com"}}
	f.entries["cn=bob,ou=people,dc=example,dc=com"] = map[string][]string{"cn": {"bob"}, "mail": {"bob@example.com"}}
}

func TestSearchScopesAndBaseFallback(t *testing.T) {
	f := newFakeConn()
	seedDirectory(f)
	c := newWithTransport(f, Config{Base: "dc=example,dc=com"})

	// Subtree from the configured base (empty req.Base uses it).
	res, err := c.Search(&SearchRequest{Scope: ScopeSubtree})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 4 {
		t.Fatalf("subtree: %d", len(res.Entries))
	}
	if r := c.OperationResult(); r.Name != "Success" {
		t.Fatalf("result: %+v", r)
	}

	// Single level below ou=people: alice and bob.
	res, _ = c.Search(&SearchRequest{Base: "ou=people,dc=example,dc=com", Scope: ScopeSingleLevel})
	if len(res.Entries) != 2 {
		t.Fatalf("onelevel: %d", len(res.Entries))
	}

	// Base object only.
	res, _ = c.Search(&SearchRequest{Base: "cn=alice,ou=people,dc=example,dc=com", Scope: ScopeBase})
	if len(res.Entries) != 1 {
		t.Fatalf("base: %d", len(res.Entries))
	}
	e := res.Entries[0]
	if e.DN() != "cn=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("dn: %q", e.DN())
	}
	if e.First("CN") != "alice" { // case-insensitive
		t.Fatalf("cn: %q", e.First("CN"))
	}
	if got := e.Get("mail"); len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("mail: %v", got)
	}
	if e.Get("absent") != nil || e.First("absent") != "" {
		t.Fatal("absent attribute should be nil/empty")
	}
	if names := e.AttributeNames(); len(names) != 2 || names[0] != "cn" || names[1] != "mail" {
		t.Fatalf("names: %v", names)
	}

	// Size limit caps the entries returned.
	res, _ = c.Search(&SearchRequest{Scope: ScopeSubtree, SizeLimit: 1})
	if len(res.Entries) != 1 {
		t.Fatalf("sizelimit: %d", len(res.Entries))
	}
}

func TestSearchError(t *testing.T) {
	f := newFakeConn()
	f.errSearch = &goldap.Error{ResultCode: goldap.LDAPResultNoSuchObject, Err: strErr("no base")}
	c := newWithTransport(f, Config{})
	if _, err := c.Search(&SearchRequest{Base: "dc=x"}); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("expected no such object, got %v", err)
	}
}

func TestSearchEach(t *testing.T) {
	f := newFakeConn()
	seedDirectory(f)
	c := newWithTransport(f, Config{Base: "dc=example,dc=com"})
	var dns []string
	n, err := c.SearchEach(&SearchRequest{Scope: ScopeSubtree}, func(e *Entry) { dns = append(dns, e.DN()) })
	if err != nil || n != 4 || len(dns) != 4 {
		t.Fatalf("each: n=%d err=%v dns=%v", n, err, dns)
	}
	// Error path.
	f.errSearch = strErr("boom")
	if _, err := c.SearchEach(&SearchRequest{}, func(*Entry) {}); err == nil {
		t.Fatal("expected each error")
	}
}

func TestNewEntryDuplicateFoldedName(t *testing.T) {
	// Two attributes folding to the same lower-case name: the first-seen casing
	// is remembered, the second is skipped.
	ge := &goldap.Entry{DN: "cn=x", Attributes: []*goldap.EntryAttribute{
		{Name: "CN", Values: []string{"first"}},
		{Name: "cn", Values: []string{"second"}},
	}}
	e := newEntry(ge)
	if got := e.First("cn"); got != "second" {
		t.Fatalf("value: %q", got) // second write wins in the value map
	}
	if names := e.AttributeNames(); len(names) != 1 || names[0] != "CN" {
		t.Fatalf("names: %v", names) // original casing of first-seen
	}
}

// --- modify.go ---

func TestAddModifyDeleteRename(t *testing.T) {
	f := newFakeConn()
	f.entries["dc=example,dc=com"] = map[string][]string{"dc": {"example"}}
	c := newWithTransport(f, Config{})

	dn := "cn=carol,dc=example,dc=com"
	if err := c.Add(dn, map[string][]string{"cn": {"carol"}, "sn": {"c"}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Adding again already exists.
	if err := c.Add(dn, map[string][]string{"cn": {"carol"}}); !errors.Is(err, ErrEntryAlreadyExists) {
		t.Fatalf("expected already-exists, got %v", err)
	}

	// Modify: replace, add, delete in one call.
	err := c.Modify(dn, []ModifyOp{
		{Type: ModReplace, Attr: "sn", Values: []string{"carroll"}},
		{Type: ModAdd, Attr: "mail", Values: []string{"carol@example.com"}},
		{Type: ModDelete, Attr: "cn"},
	})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if got := f.entries[dn]["sn"]; len(got) != 1 || got[0] != "carroll" {
		t.Fatalf("sn: %v", got)
	}
	if _, ok := f.entries[dn]["cn"]; ok {
		t.Fatal("cn should be deleted")
	}

	// Convenience wrappers.
	if err := c.ReplaceAttribute(dn, "sn", []string{"C."}); err != nil {
		t.Fatalf("replace attr: %v", err)
	}
	if err := c.AddAttribute(dn, "telephoneNumber", []string{"123"}); err != nil {
		t.Fatalf("add attr: %v", err)
	}
	if err := c.DeleteAttribute(dn, "telephoneNumber"); err != nil {
		t.Fatalf("del attr: %v", err)
	}

	// Rename within the same parent.
	if err := c.Rename(dn, "cn=caroline", true, ""); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, ok := f.entries["cn=caroline,dc=example,dc=com"]; !ok {
		t.Fatal("renamed entry missing")
	}

	// Delete.
	if err := c.Delete("cn=caroline,dc=example,dc=com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := c.Delete("cn=caroline,dc=example,dc=com"); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("expected no such object, got %v", err)
	}
}

func TestRenameNewSuperior(t *testing.T) {
	f := newFakeConn()
	f.entries["cn=x,ou=a,dc=e"] = map[string][]string{"cn": {"x"}}
	c := newWithTransport(f, Config{})
	if err := c.Rename("cn=x,ou=a,dc=e", "cn=x", true, "ou=b,dc=e"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, ok := f.entries["cn=x,ou=b,dc=e"]; !ok {
		t.Fatal("moved entry missing")
	}
}

func TestModifyErrorBranches(t *testing.T) {
	f := newFakeConn()
	c := newWithTransport(f, Config{})

	f.errAdd = strErr("a")
	if err := c.Add("dn", nil); err == nil {
		t.Fatal("add error")
	}
	f.errModify = strErr("m")
	if err := c.Modify("dn", []ModifyOp{{Type: ModAdd, Attr: "x", Values: []string{"1"}}}); err == nil {
		t.Fatal("modify error")
	}
	f.errDel = strErr("d")
	if err := c.Delete("dn"); err == nil {
		t.Fatal("del error")
	}
	f.errModDN = strErr("r")
	if err := c.Rename("dn", "cn=y", false, ""); err == nil {
		t.Fatal("rename error")
	}
	// Modify against a missing DN (no injected error) returns NoSuchObject.
	f.errModify = nil
	if err := c.Modify("cn=missing,dc=e", []ModifyOp{{Type: ModReplace, Attr: "x", Values: []string{"1"}}}); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("expected no such object, got %v", err)
	}
}

func TestCompare(t *testing.T) {
	f := newFakeConn()
	f.compareResult = true
	c := newWithTransport(f, Config{})
	ok, err := c.Compare("cn=x", "cn", "x")
	if err != nil || !ok {
		t.Fatalf("compare true: %v %v", ok, err)
	}
	f.compareResult = false
	if ok, _ := c.Compare("cn=x", "cn", "y"); ok {
		t.Fatal("compare should be false")
	}
	f.errCompare = strErr("c")
	if _, err := c.Compare("cn=x", "cn", "z"); err == nil {
		t.Fatal("compare error")
	}
}
