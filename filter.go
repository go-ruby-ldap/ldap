// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Filter is an RFC 4515 search filter, mirroring Net::LDAP::Filter. It wraps the
// filter's parenthesised string form and composes with [And], [Or] and [Not].
// Build a leaf with [Eq], [Present], [Ge], [Le], [Contains], [Begins], [Ends] or
// [Approx]; parse one from a string with [Construct]. Attribute values are
// escaped per RFC 4515, so a value containing "(", ")", "*" or "\" is safe.
type Filter struct {
	s string
}

// String returns the filter's RFC 4515 parenthesised string form, mirroring
// Net::LDAP::Filter#to_s. The zero Filter renders as the present-everything
// filter "(objectClass=*)", matching net-ldap's default.
func (f Filter) String() string {
	if f.s == "" {
		return "(objectClass=*)"
	}
	return f.s
}

// esc escapes an assertion value per RFC 4515 so it is safe inside a filter.
func esc(v string) string { return goldap.EscapeFilter(v) }

// Eq builds an equality filter (attr=value), mirroring Net::LDAP::Filter.eq. A
// value of "*" is preserved so Eq(attr, "*") is the presence filter, matching
// net-ldap.
func Eq(attr, value string) Filter {
	if value == "*" {
		return Present(attr)
	}
	return Filter{s: "(" + attr + "=" + esc(value) + ")"}
}

// Present builds a presence filter (attr=*), mirroring Net::LDAP::Filter.present
// / .pres.
func Present(attr string) Filter { return Filter{s: "(" + attr + "=*)"} }

// Ge builds a greater-or-equal filter (attr>=value), mirroring
// Net::LDAP::Filter.ge.
func Ge(attr, value string) Filter { return Filter{s: "(" + attr + ">=" + esc(value) + ")"} }

// Le builds a less-or-equal filter (attr<=value), mirroring
// Net::LDAP::Filter.le.
func Le(attr, value string) Filter { return Filter{s: "(" + attr + "<=" + esc(value) + ")"} }

// Approx builds an approximate-match filter (attr~=value), mirroring
// Net::LDAP::Filter with the :approx operator.
func Approx(attr, value string) Filter { return Filter{s: "(" + attr + "~=" + esc(value) + ")"} }

// Contains builds a substring filter matching values containing value
// (attr=*value*), mirroring Net::LDAP::Filter.contains.
func Contains(attr, value string) Filter { return Filter{s: "(" + attr + "=*" + esc(value) + "*)"} }

// Begins builds a substring filter matching values beginning with value
// (attr=value*), mirroring Net::LDAP::Filter.begins.
func Begins(attr, value string) Filter { return Filter{s: "(" + attr + "=" + esc(value) + "*)"} }

// Ends builds a substring filter matching values ending with value
// (attr=*value), mirroring Net::LDAP::Filter.ends.
func Ends(attr, value string) Filter { return Filter{s: "(" + attr + "=*" + esc(value) + ")"} }

// And joins filters with a logical AND (&(f1)(f2)...), mirroring
// Net::LDAP::Filter#& and Filter.join. A single filter is returned unchanged and
// an empty call yields the zero Filter.
func And(filters ...Filter) Filter { return combine("&", filters) }

// Or joins filters with a logical OR (|(f1)(f2)...), mirroring
// Net::LDAP::Filter#| and Filter.intersect.
func Or(filters ...Filter) Filter { return combine("|", filters) }

// Not negates a filter (!(f)), mirroring Net::LDAP::Filter#~ and Filter.negate.
func Not(f Filter) Filter { return Filter{s: "(!" + f.String() + ")"} }

// combine builds a compound filter with the given operator, returning a lone
// filter unchanged so And(f) == f.
func combine(op string, filters []Filter) Filter {
	switch len(filters) {
	case 0:
		return Filter{}
	case 1:
		return filters[0]
	}
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(op)
	for _, f := range filters {
		b.WriteString(f.String())
	}
	b.WriteByte(')')
	return Filter{s: b.String()}
}

// Construct parses an RFC 4515 filter string into a [Filter], mirroring
// Net::LDAP::Filter.construct / from_rfc2254. It validates the string by
// compiling it, returning [ErrFilterCompile] wrapping the compile error when the
// string is not a valid filter.
func Construct(s string) (Filter, error) {
	if _, err := goldap.CompileFilter(s); err != nil {
		return Filter{}, &Error{Code: CodeFilterCompile, Name: "FilterSyntax", Message: err.Error(), cause: err}
	}
	return Filter{s: s}, nil
}
