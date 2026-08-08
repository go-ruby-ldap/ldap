// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import goldap "github.com/go-ldap/ldap/v3"

// ModType is the kind of change a [ModifyOp] applies to an attribute, mirroring
// the operation symbols of Net::LDAP#modify (:add, :replace, :delete).
type ModType int

const (
	// ModAdd adds values to an attribute (the :add operation).
	ModAdd ModType = iota
	// ModReplace replaces an attribute's values (the :replace operation).
	ModReplace
	// ModDelete deletes values from an attribute, or the whole attribute when
	// Values is empty (the :delete operation).
	ModDelete
)

// ModifyOp is one change within a [Client.Modify], mirroring an element of the
// operations: array net-ldap passes to #modify: [type, attribute, values].
type ModifyOp struct {
	Type   ModType
	Attr   string
	Values []string
}

// Add creates the entry dn with the given attributes, mirroring
// Net::LDAP#add(dn:, attributes:). attributes maps each attribute name to its
// values. It records the operation result and returns [ErrEntryAlreadyExists]
// when dn already exists.
func (c *Client) Add(dn string, attributes map[string][]string) error {
	req := goldap.NewAddRequest(dn, nil)
	for attr, vals := range attributes {
		req.Attribute(attr, vals)
	}
	return c.record(c.t.Add(req))
}

// Modify applies ops to the entry dn, mirroring Net::LDAP#modify(dn:,
// operations:). Each op adds, replaces or deletes an attribute's values. It
// records the operation result.
func (c *Client) Modify(dn string, ops []ModifyOp) error {
	req := goldap.NewModifyRequest(dn, nil)
	for _, op := range ops {
		switch op.Type {
		case ModAdd:
			req.Add(op.Attr, op.Values)
		case ModReplace:
			req.Replace(op.Attr, op.Values)
		default: // ModDelete
			req.Delete(op.Attr, op.Values)
		}
	}
	return c.record(c.t.Modify(req))
}

// ReplaceAttribute replaces attr's values on dn, the common single-attribute
// case of Net::LDAP#replace_attribute.
func (c *Client) ReplaceAttribute(dn, attr string, values []string) error {
	return c.Modify(dn, []ModifyOp{{Type: ModReplace, Attr: attr, Values: values}})
}

// AddAttribute adds values to attr on dn, mirroring Net::LDAP#add_attribute.
func (c *Client) AddAttribute(dn, attr string, values []string) error {
	return c.Modify(dn, []ModifyOp{{Type: ModAdd, Attr: attr, Values: values}})
}

// DeleteAttribute deletes attr from dn, mirroring Net::LDAP#delete_attribute.
func (c *Client) DeleteAttribute(dn, attr string) error {
	return c.Modify(dn, []ModifyOp{{Type: ModDelete, Attr: attr}})
}

// Delete removes the entry dn, mirroring Net::LDAP#delete(dn:). It records the
// operation result and returns [ErrNoSuchObject] when dn does not exist.
func (c *Client) Delete(dn string) error {
	return c.record(c.t.Del(goldap.NewDelRequest(dn, nil)))
}

// Rename changes an entry's relative distinguished name, mirroring
// Net::LDAP#rename / #modify_rdn(olddn:, newrdn:, delete_attributes:,
// new_superior:). deleteOld removes the old RDN attribute value; newSuperior, if
// non-empty, moves the entry under a new parent. It records the operation
// result.
func (c *Client) Rename(dn, newRDN string, deleteOld bool, newSuperior string) error {
	return c.record(c.t.ModifyDN(goldap.NewModifyDNRequest(dn, newRDN, deleteOld, newSuperior)))
}

// Compare reports whether dn's attr has the given value, mirroring
// Net::LDAP#compare. It records the operation result; a false comparison is not
// an error.
func (c *Client) Compare(dn, attr, value string) (bool, error) {
	ok, err := c.t.Compare(dn, attr, value)
	if err != nil {
		return false, c.record(err)
	}
	_ = c.record(nil)
	return ok, nil
}
