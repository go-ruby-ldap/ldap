// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"sort"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Scope is a search scope, mirroring the values Net::LDAP#search accepts for its
// scope: keyword.
type Scope int

const (
	// ScopeBase searches only the base object (Net::LDAP::SearchScope_BaseObject).
	ScopeBase Scope = Scope(goldap.ScopeBaseObject)
	// ScopeSingleLevel searches the base's immediate children
	// (Net::LDAP::SearchScope_SingleLevel).
	ScopeSingleLevel Scope = Scope(goldap.ScopeSingleLevel)
	// ScopeSubtree searches the base and its whole subtree, the net-ldap default
	// (Net::LDAP::SearchScope_WholeSubtree).
	ScopeSubtree Scope = Scope(goldap.ScopeWholeSubtree)
)

// Entry mirrors Net::LDAP::Entry: a distinguished name and its attributes, with
// case-insensitive attribute access (LDAP attribute names are case-insensitive).
type Entry struct {
	dn    string
	attrs map[string][]string // keyed by lower-cased attribute name
	names map[string]string   // lower-cased name -> first-seen original casing
}

// newEntry builds an Entry from a go-ldap entry, folding attribute names to
// lower case for case-insensitive lookup while remembering their original
// casing for [Entry.AttributeNames].
func newEntry(e *goldap.Entry) *Entry {
	out := &Entry{dn: e.DN, attrs: make(map[string][]string, len(e.Attributes)), names: make(map[string]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		lc := strings.ToLower(a.Name)
		out.attrs[lc] = a.Values
		if _, seen := out.names[lc]; !seen {
			out.names[lc] = a.Name
		}
	}
	return out
}

// DN returns the entry's distinguished name, mirroring Net::LDAP::Entry#dn.
func (e *Entry) DN() string { return e.dn }

// Get returns the values of attr (case-insensitive), or nil when the entry has
// no such attribute. It mirrors Net::LDAP::Entry#[] / #attribute, which are
// case-insensitive and always return an array.
func (e *Entry) Get(attr string) []string { return e.attrs[strings.ToLower(attr)] }

// First returns the first value of attr (case-insensitive), or "" when the
// entry has no such attribute, mirroring the common entry[:cn].first idiom.
func (e *Entry) First(attr string) string {
	if v := e.attrs[strings.ToLower(attr)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// AttributeNames returns the entry's attribute names in their original casing,
// sorted, mirroring Net::LDAP::Entry#attribute_names.
func (e *Entry) AttributeNames() []string {
	out := make([]string, 0, len(e.names))
	for _, orig := range e.names {
		out = append(out, orig)
	}
	sort.Strings(out)
	return out
}

// SearchRequest describes a search, mirroring the keywords of Net::LDAP#search.
type SearchRequest struct {
	// Base is the search base DN; empty uses the client's configured Base.
	Base string
	// Scope is the search scope; the zero value ScopeBase is net-ldap's
	// SearchScope_BaseObject. Callers commonly set ScopeSubtree.
	Scope Scope
	// Filter is the search filter; the zero Filter is "(objectClass=*)".
	Filter Filter
	// Attributes lists the attributes to return; empty returns all user
	// attributes.
	Attributes []string
	// SizeLimit caps the number of entries returned; 0 means no limit.
	SizeLimit int
	// TimeLimit caps the server-side search time in seconds; 0 means no limit.
	TimeLimit int
	// TypesOnly asks the directory to return attribute names without values.
	TypesOnly bool
}

// SearchResult is the reply to Search: the matched entries. It mirrors the array
// of Net::LDAP::Entry that Net::LDAP#search returns.
type SearchResult struct {
	Entries []*Entry
}

// Search runs an LDAP search and returns the matched entries. It mirrors
// Net::LDAP#search: an empty req.Base falls back to the client's configured
// base, the zero filter matches every object, and the result records the
// operation outcome (see [Client.OperationResult]). A no-such-object base
// returns [ErrNoSuchObject].
func (c *Client) Search(req *SearchRequest) (*SearchResult, error) {
	base := req.Base
	if base == "" {
		base = c.base
	}
	sr := goldap.NewSearchRequest(
		base,
		int(req.Scope),
		goldap.NeverDerefAliases,
		req.SizeLimit,
		req.TimeLimit,
		req.TypesOnly,
		req.Filter.String(),
		req.Attributes,
		nil,
	)
	res, err := c.t.Search(sr)
	if err != nil {
		return nil, c.record(err)
	}
	_ = c.record(nil)
	out := &SearchResult{Entries: make([]*Entry, len(res.Entries))}
	for i, e := range res.Entries {
		out.Entries[i] = newEntry(e)
	}
	return out, nil
}

// SearchEach runs a search and invokes fn with each matched entry, mirroring the
// block form Net::LDAP#search(...) { |entry| ... }. It returns the number of
// entries delivered.
func (c *Client) SearchEach(req *SearchRequest, fn func(*Entry)) (int, error) {
	res, err := c.Search(req)
	if err != nil {
		return 0, err
	}
	for _, e := range res.Entries {
		fn(e)
	}
	return len(res.Entries), nil
}
