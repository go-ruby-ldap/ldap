// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// transport is the host seam. Its method set is satisfied directly by
// *ldap.Conn, so [New] injects a real connection with no adapter, while tests
// inject a deterministic in-memory implementation. Keeping the seam in terms of
// the go-ldap request/response types means the Client's request-building and
// response-mapping logic is exercised identically whether the backend is real
// or fake, which is what lets the deterministic suite reach 100% coverage
// without a live directory.
type transport interface {
	Bind(username, password string) error
	UnauthenticatedBind(username string) error
	Search(req *goldap.SearchRequest) (*goldap.SearchResult, error)
	Add(req *goldap.AddRequest) error
	Modify(req *goldap.ModifyRequest) error
	Del(req *goldap.DelRequest) error
	ModifyDN(req *goldap.ModifyDNRequest) error
	Compare(dn, attribute, value string) (bool, error)
	Close() error
}

// Config configures a [Client]. The fields mirror the keywords Net::LDAP.new
// accepts: the directory host and port, the default search base, the simple-bind
// credentials (auth: {method: :simple, username:, password:}) and, when the
// connection is encrypted, a TLS config (encryption: :simple_tls).
type Config struct {
	// Host is the directory host. Defaults to "127.0.0.1" when empty.
	Host string
	// Port is the directory port. Defaults to 389 (or 636 when TLS is set).
	Port int
	// Base is the default search base DN used when a SearchRequest omits one.
	Base string
	// Method is the bind method; only "simple" (the default) and "anonymous"
	// are supported. "anonymous" performs an unauthenticated bind.
	Method string
	// Username and Password are the simple-bind credentials.
	Username string
	Password string
	// TLS, when set, connects with ldaps:// (LDAP over TLS). nil means plaintext
	// ldap://.
	TLS *tls.Config
	// URL, when set, overrides Host/Port/TLS with an explicit ldap:// or
	// ldaps:// URL, mirroring net-ldap's acceptance of a full URI.
	URL string
}

// OperationResult mirrors Net::LDAP#get_operation_result: the LDAP result code,
// its net-ldap name, the human-readable message and the matched DN of the last
// operation a [Client] performed. Code 0 (Success) means the last operation
// succeeded.
type OperationResult struct {
	Code      uint16
	Name      string
	Message   string
	MatchedDN string
}

// Client is a Net::LDAP connection bound to a transport seam. It mirrors the
// net-ldap connection object: it builds requests, drives them over the
// transport, records each operation's result (see [Client.OperationResult]) and
// maps replies to net-ldap's value and error model. Construct one with [New];
// the zero value is not usable.
type Client struct {
	t        transport
	base     string
	method   string
	username string
	password string
	result   OperationResult
}

// New connects to the directory using cfg and returns a [Client]. It dials the
// connection (failing with [ErrNetwork] when the directory is unreachable) but
// does not bind: call [Client.Bind] to authenticate, mirroring net-ldap where
// the connection opens lazily and #bind authenticates.
func New(cfg Config) (*Client, error) {
	dialURL, err := configURL(cfg)
	if err != nil {
		return nil, err
	}
	var conn *goldap.Conn
	if cfg.TLS != nil {
		conn, err = goldap.DialURL(dialURL, goldap.DialWithTLSConfig(cfg.TLS))
	} else {
		conn, err = goldap.DialURL(dialURL)
	}
	if err != nil {
		return nil, mapError(err)
	}
	return newWithTransport(conn, cfg), nil
}

// newWithTransport wraps an arbitrary transport with cfg's identity. It is the
// seam tests use to drive the Client against a deterministic in-memory backend.
func newWithTransport(t transport, cfg Config) *Client {
	method := cfg.Method
	if method == "" {
		method = "simple"
	}
	return &Client{
		t:        t,
		base:     cfg.Base,
		method:   method,
		username: cfg.Username,
		password: cfg.Password,
		result:   OperationResult{Name: "Success"},
	}
}

// configURL builds the ldap:// or ldaps:// URL New dials, honouring an explicit
// cfg.URL and otherwise composing host and port (defaulting host to
// 127.0.0.1 and port to 389, or 636 under TLS). A malformed explicit URL
// returns [ErrNetwork].
func configURL(cfg Config) (string, error) {
	if cfg.URL != "" {
		if _, err := url.Parse(cfg.URL); err != nil {
			return "", &Error{Code: CodeNetwork, Name: "Network", Message: err.Error(), cause: err}
		}
		return cfg.URL, nil
	}
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	scheme := "ldap"
	port := cfg.Port
	if cfg.TLS != nil {
		scheme = "ldaps"
		if port == 0 {
			port = 636
		}
	}
	if port == 0 {
		port = 389
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port), nil
}

// Base returns the default search base the client was configured with.
func (c *Client) Base() string { return c.base }

// OperationResult returns the result of the last operation the client
// performed, mirroring Net::LDAP#get_operation_result. It is a fresh Success
// before any operation.
func (c *Client) OperationResult() OperationResult { return c.result }

// record sets the client's last-operation result from err (a Success result
// when err is nil) and returns the mapped error, so every operation both
// updates get_operation_result and returns an idiomatic Go error.
func (c *Client) record(err error) error {
	if err == nil {
		c.result = OperationResult{Code: goldap.LDAPResultSuccess, Name: "Success", Message: "Success"}
		return nil
	}
	me := mapError(err).(*Error)
	matched := ""
	var le *goldap.Error
	if errors.As(err, &le) {
		matched = le.MatchedDN
	}
	c.result = OperationResult{Code: me.Code, Name: me.Name, Message: me.Message, MatchedDN: matched}
	return me
}

// Bind authenticates the connection with the configured credentials. A "simple"
// method performs a simple bind with the username and password; an "anonymous"
// method performs an unauthenticated bind with the username. It mirrors
// net-ldap's #bind and records the result, so a failed bind leaves an
// [ErrInvalidCredentials] (or other) result on the client.
func (c *Client) Bind() error {
	if strings.EqualFold(c.method, "anonymous") {
		return c.record(c.t.UnauthenticatedBind(c.username))
	}
	return c.record(c.t.Bind(c.username, c.password))
}

// BindWith authenticates with an explicit username and password (a simple
// bind), mirroring net-ldap's #bind(method: :simple, username:, password:) with
// per-call credentials.
func (c *Client) BindWith(username, password string) error {
	return c.record(c.t.Bind(username, password))
}

// Close releases the connection's resources, mirroring net-ldap closing the
// connection.
func (c *Client) Close() error { return c.t.Close() }
