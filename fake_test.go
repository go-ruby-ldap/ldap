// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// fakeConn is a deterministic, in-process implementation of the transport seam.
// It is not a full directory: it is a faithful-enough bind/search/add/modify/
// delete/rename/compare stand-in that lets every line of the Client's request-
// building and response-mapping logic run with no external server and no cgo, so
// the suite holds 100% coverage on every arch under qemu. Real filter and
// directory semantics are validated separately by the "live" in-process LDAP
// server suite. Search deliberately ignores the assertion filter (the wrapper's
// job is request-building and result-mapping, exercised regardless); scope,
// size-limit and the entry mapping are honoured.
type fakeConn struct {
	// entries maps a DN to its attributes (attribute name -> values).
	entries map[string]map[string][]string
	// validUser/validPassword are the credentials a simple Bind accepts.
	validUser     string
	validPassword string

	// Injected outcomes for exercising error branches.
	errBind, errSearch, errAdd  error
	errModify, errDel, errModDN error
	errCompare, errClose        error
	compareResult               bool
}

func newFakeConn() *fakeConn {
	return &fakeConn{entries: map[string]map[string][]string{}}
}

// invalidCreds is the error a rejected simple bind returns, an *ldap.Error so it
// maps through the net-ldap error tree exactly as a real rejection would.
func invalidCreds() error {
	return &goldap.Error{ResultCode: goldap.LDAPResultInvalidCredentials, Err: strErr("invalid credentials")}
}

// noSuchObject is the error operations return for a missing DN.
func noSuchObject(dn string) error {
	return &goldap.Error{ResultCode: goldap.LDAPResultNoSuchObject, MatchedDN: dn, Err: strErr("no such object")}
}

// strErr is a tiny error type so the fake can attach messages without importing
// errors in every helper.
type strErr string

func (e strErr) Error() string { return string(e) }

func (f *fakeConn) Bind(username, password string) error {
	if f.errBind != nil {
		return f.errBind
	}
	if username == f.validUser && password == f.validPassword {
		return nil
	}
	return invalidCreds()
}

func (f *fakeConn) UnauthenticatedBind(username string) error { return f.errBind }

func (f *fakeConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if f.errSearch != nil {
		return nil, f.errSearch
	}
	base := strings.ToLower(req.BaseDN)
	var dns []string
	for dn := range f.entries {
		if inScope(strings.ToLower(dn), base, req.Scope) {
			dns = append(dns, dn)
		}
	}
	sort.Strings(dns) // deterministic order regardless of map iteration
	res := &goldap.SearchResult{}
	for _, dn := range dns {
		if req.SizeLimit > 0 && len(res.Entries) >= req.SizeLimit {
			break
		}
		e := &goldap.Entry{DN: dn}
		var names []string
		for name := range f.entries[dn] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			e.Attributes = append(e.Attributes, &goldap.EntryAttribute{Name: name, Values: f.entries[dn][name]})
		}
		res.Entries = append(res.Entries, e)
	}
	return res, nil
}

// inScope reports whether dn falls within base at the given LDAP scope. All
// arguments are lower-cased.
func inScope(dn, base string, scope int) bool {
	switch scope {
	case goldap.ScopeBaseObject:
		return dn == base
	case goldap.ScopeSingleLevel:
		if !strings.HasSuffix(dn, ","+base) {
			return false
		}
		rdn := strings.TrimSuffix(dn, ","+base)
		return !strings.Contains(rdn, ",")
	default: // ScopeWholeSubtree
		return dn == base || strings.HasSuffix(dn, ","+base)
	}
}

func (f *fakeConn) Add(req *goldap.AddRequest) error {
	if f.errAdd != nil {
		return f.errAdd
	}
	if _, ok := f.entries[req.DN]; ok {
		return &goldap.Error{ResultCode: goldap.LDAPResultEntryAlreadyExists, MatchedDN: req.DN, Err: strErr("already exists")}
	}
	attrs := map[string][]string{}
	for _, a := range req.Attributes {
		attrs[a.Type] = a.Vals
	}
	f.entries[req.DN] = attrs
	return nil
}

func (f *fakeConn) Modify(req *goldap.ModifyRequest) error {
	if f.errModify != nil {
		return f.errModify
	}
	attrs, ok := f.entries[req.DN]
	if !ok {
		return noSuchObject(req.DN)
	}
	for _, ch := range req.Changes {
		t := ch.Modification.Type
		switch ch.Operation {
		case goldap.AddAttribute:
			attrs[t] = append(attrs[t], ch.Modification.Vals...)
		case goldap.ReplaceAttribute:
			attrs[t] = ch.Modification.Vals
		default: // DeleteAttribute
			delete(attrs, t)
		}
	}
	return nil
}

func (f *fakeConn) Del(req *goldap.DelRequest) error {
	if f.errDel != nil {
		return f.errDel
	}
	if _, ok := f.entries[req.DN]; !ok {
		return noSuchObject(req.DN)
	}
	delete(f.entries, req.DN)
	return nil
}

func (f *fakeConn) ModifyDN(req *goldap.ModifyDNRequest) error {
	if f.errModDN != nil {
		return f.errModDN
	}
	attrs, ok := f.entries[req.DN]
	if !ok {
		return noSuchObject(req.DN)
	}
	parent := req.NewSuperior
	if parent == "" {
		if i := strings.Index(req.DN, ","); i >= 0 {
			parent = req.DN[i+1:]
		}
	}
	newDN := req.NewRDN
	if parent != "" {
		newDN = req.NewRDN + "," + parent
	}
	delete(f.entries, req.DN)
	f.entries[newDN] = attrs
	return nil
}

func (f *fakeConn) Compare(dn, attribute, value string) (bool, error) {
	if f.errCompare != nil {
		return false, f.errCompare
	}
	return f.compareResult, nil
}

func (f *fakeConn) Close() error { return f.errClose }
