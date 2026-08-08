// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"errors"
	"testing"
)

func TestFilterLeaves(t *testing.T) {
	cases := []struct {
		got  Filter
		want string
	}{
		{Eq("cn", "alice"), "(cn=alice)"},
		{Eq("cn", "*"), "(cn=*)"}, // "*" value is the presence filter
		{Present("mail"), "(mail=*)"},
		{Ge("age", "18"), "(age>=18)"},
		{Le("age", "65"), "(age<=65)"},
		{Approx("sn", "smyth"), "(sn~=smyth)"},
		{Contains("cn", "li"), "(cn=*li*)"},
		{Begins("cn", "al"), "(cn=al*)"},
		{Ends("cn", "ce"), "(cn=*ce)"},
	}
	for _, tc := range cases {
		if got := tc.got.String(); got != tc.want {
			t.Fatalf("filter = %q, want %q", got, tc.want)
		}
	}
}

func TestFilterEscaping(t *testing.T) {
	// Special characters in a value are escaped per RFC 4515.
	if got := Eq("cn", "a*b(c)").String(); got != `(cn=a\2ab\28c\29)` {
		t.Fatalf("escaped filter: %q", got)
	}
}

func TestFilterZeroValue(t *testing.T) {
	var f Filter
	if got := f.String(); got != "(objectClass=*)" {
		t.Fatalf("zero filter: %q", got)
	}
}

func TestFilterCombine(t *testing.T) {
	a := Eq("cn", "alice")
	b := Present("mail")
	cc := Eq("ou", "people")

	// And with zero, one and many operands.
	if got := And().String(); got != "(objectClass=*)" {
		t.Fatalf("empty And: %q", got)
	}
	if got := And(a).String(); got != "(cn=alice)" {
		t.Fatalf("single And: %q", got)
	}
	if got := And(a, b, cc).String(); got != "(&(cn=alice)(mail=*)(ou=people))" {
		t.Fatalf("And: %q", got)
	}
	if got := Or(a, b).String(); got != "(|(cn=alice)(mail=*))" {
		t.Fatalf("Or: %q", got)
	}
	if got := Not(a).String(); got != "(!(cn=alice))" {
		t.Fatalf("Not: %q", got)
	}
}

func TestFilterConstruct(t *testing.T) {
	f, err := Construct("(&(objectClass=person)(cn=al*))")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if f.String() != "(&(objectClass=person)(cn=al*))" {
		t.Fatalf("round-trip: %q", f.String())
	}
	// A malformed filter string reports a filter-syntax error.
	if _, err := Construct("(cn=al"); !errors.Is(err, ErrFilterCompile) {
		t.Fatalf("expected filter-compile error, got %v", err)
	}
}
