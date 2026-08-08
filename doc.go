// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package ldap is a pure-Go (CGO=0), MRI-faithful reimplementation of the Ruby
// net-ldap gem's Net::LDAP client surface.
//
// It does not reimplement the LDAP protocol. It consumes the official pure-Go
// client github.com/go-ldap/ldap/v3 as its transport and layers the ergonomics
// and result/error model of net-ldap on top: Client.Bind, Search (base / single
// level / whole subtree scopes), Add, Modify (add / replace / delete
// operations), Delete, Rename (modify RDN), a Filter builder mirroring
// Net::LDAP::Filter (eq / present / substrings / ge / le / and / or / not and a
// Construct string parser), an Entry with case-insensitive attribute access
// mirroring Net::LDAP::Entry, and an OperationResult mirroring
// Net::LDAP#get_operation_result.
//
// # Transport is a host seam
//
// A Client drives an injected [transport] whose method set is satisfied
// directly by *ldap.Conn (no adapter). This makes every method's request-
// building and response-mapping logic testable against a deterministic
// in-memory transport with no external directory and no cgo, so the suite
// reaches 100% coverage on every arch under qemu. A separate live suite (the
// nested ./live module) drives an in-process pure-Go LDAP server for real
// round-trip validation on native lanes.
//
// # Ruby mapping
//
//	Net::LDAP.new(host:, port:, base:, auth:)  =>  ldap.New(ldap.Config{...})
//	ldap.bind                                  =>  c.Bind()
//	ldap.search(filter:, base:, &block)        =>  c.Search(&ldap.SearchRequest{...})
//	ldap.add(dn:, attributes:)                 =>  c.Add(dn, attrs)
//	ldap.modify(dn:, operations:)              =>  c.Modify(dn, ops)
//	ldap.delete(dn:)                           =>  c.Delete(dn)
//	ldap.rename(olddn:, newrdn:)               =>  c.Rename(olddn, newrdn, true, "")
//	Net::LDAP::Filter.eq("cn", "a")            =>  ldap.Eq("cn", "a")
//	Net::LDAP::Filter.construct("(cn=a)")      =>  ldap.Construct("(cn=a)")
//	ldap.get_operation_result                  =>  c.OperationResult()
package ldap
