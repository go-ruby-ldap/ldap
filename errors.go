// Copyright (c) the go-ruby-ldap/ldap authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Error is the base of the net-ldap error tree. It carries the LDAP result code
// the directory returned (or a synthetic client-side code) and mirrors the
// net-ldap gem, whose exceptions map onto LDAP result codes. Match a specific
// kind with [errors.Is] against one of the exported sentinels (for example
// [ErrNoSuchObject]); the match is by code, so a wrapped Error compares equal to
// its sentinel.
type Error struct {
	// Code is the LDAP result code the operation reported.
	Code uint16
	// Name is the net-ldap error-class name for Code (e.g. "NoSuchObject").
	Name string
	// Message is the human-readable detail.
	Message string
	// cause is the underlying error, if any.
	cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("ldap: %s (%d)", e.Name, e.Code)
	}
	return fmt.Sprintf("ldap: %s (%d): %s", e.Name, e.Code, e.Message)
}

// Unwrap exposes the underlying transport error for [errors.Unwrap].
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same result code, so the
// exported sentinels match any Error of the same kind regardless of message.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Code == e.Code
}

// Synthetic client-side codes, above the LDAP protocol range, for errors that
// never come from the directory: a connection failure and a filter that would
// not compile. They mirror the go-ldap client-error codes.
const (
	// CodeNetwork is reported when the connection to the directory fails.
	CodeNetwork uint16 = 200
	// CodeFilterCompile is reported when a filter string will not compile.
	CodeFilterCompile uint16 = 201
)

// The net-ldap error tree: one sentinel per result code this package raises.
// Compare with errors.Is, e.g. errors.Is(err, ldap.ErrNoSuchObject).
var (
	ErrOperationsError     = &Error{Code: goldap.LDAPResultOperationsError, Name: "OperationsError"}
	ErrProtocolError       = &Error{Code: goldap.LDAPResultProtocolError, Name: "ProtocolError"}
	ErrTimeLimitExceeded   = &Error{Code: goldap.LDAPResultTimeLimitExceeded, Name: "TimeLimitExceeded"}
	ErrSizeLimitExceeded   = &Error{Code: goldap.LDAPResultSizeLimitExceeded, Name: "SizeLimitExceeded"}
	ErrAuthMethodNotSupp   = &Error{Code: goldap.LDAPResultAuthMethodNotSupported, Name: "AuthMethodNotSupported"}
	ErrStrongAuthRequired  = &Error{Code: goldap.LDAPResultStrongAuthRequired, Name: "StrongAuthRequired"}
	ErrNoSuchAttribute     = &Error{Code: goldap.LDAPResultNoSuchAttribute, Name: "NoSuchAttribute"}
	ErrConstraintViolation = &Error{Code: goldap.LDAPResultConstraintViolation, Name: "ConstraintViolation"}
	ErrAttributeExists     = &Error{Code: goldap.LDAPResultAttributeOrValueExists, Name: "AttributeOrValueExists"}
	ErrInvalidSyntax       = &Error{Code: goldap.LDAPResultInvalidAttributeSyntax, Name: "InvalidAttributeSyntax"}
	ErrNoSuchObject        = &Error{Code: goldap.LDAPResultNoSuchObject, Name: "NoSuchObject"}
	ErrInvalidDNSyntax     = &Error{Code: goldap.LDAPResultInvalidDNSyntax, Name: "InvalidDNSyntax"}
	ErrInappropriateAuth   = &Error{Code: goldap.LDAPResultInappropriateAuthentication, Name: "InappropriateAuthentication"}
	ErrInvalidCredentials  = &Error{Code: goldap.LDAPResultInvalidCredentials, Name: "InvalidCredentials"}
	ErrInsufficientAccess  = &Error{Code: goldap.LDAPResultInsufficientAccessRights, Name: "InsufficientAccessRights"}
	ErrBusy                = &Error{Code: goldap.LDAPResultBusy, Name: "Busy"}
	ErrUnavailable         = &Error{Code: goldap.LDAPResultUnavailable, Name: "Unavailable"}
	ErrUnwillingToPerform  = &Error{Code: goldap.LDAPResultUnwillingToPerform, Name: "UnwillingToPerform"}
	ErrNamingViolation     = &Error{Code: goldap.LDAPResultNamingViolation, Name: "NamingViolation"}
	ErrObjectClassViol     = &Error{Code: goldap.LDAPResultObjectClassViolation, Name: "ObjectClassViolation"}
	ErrNotAllowedOnNonLeaf = &Error{Code: goldap.LDAPResultNotAllowedOnNonLeaf, Name: "NotAllowedOnNonLeaf"}
	ErrNotAllowedOnRDN     = &Error{Code: goldap.LDAPResultNotAllowedOnRDN, Name: "NotAllowedOnRDN"}
	ErrEntryAlreadyExists  = &Error{Code: goldap.LDAPResultEntryAlreadyExists, Name: "EntryAlreadyExists"}
	ErrOther               = &Error{Code: goldap.LDAPResultOther, Name: "Other"}
	// Client-side, non-protocol errors.
	ErrNetwork       = &Error{Code: CodeNetwork, Name: "Network"}
	ErrFilterCompile = &Error{Code: CodeFilterCompile, Name: "FilterSyntax"}
)

// codeName maps a result code to its net-ldap error-class name. Codes absent
// from the map fall back to the description in go-ldap's result-code map (or
// "Error"), so every directory reply maps to a stable, human-readable name.
var codeName = map[uint16]string{
	goldap.LDAPResultOperationsError:             "OperationsError",
	goldap.LDAPResultProtocolError:               "ProtocolError",
	goldap.LDAPResultTimeLimitExceeded:           "TimeLimitExceeded",
	goldap.LDAPResultSizeLimitExceeded:           "SizeLimitExceeded",
	goldap.LDAPResultAuthMethodNotSupported:      "AuthMethodNotSupported",
	goldap.LDAPResultStrongAuthRequired:          "StrongAuthRequired",
	goldap.LDAPResultAdminLimitExceeded:          "AdminLimitExceeded",
	goldap.LDAPResultConfidentialityRequired:     "ConfidentialityRequired",
	goldap.LDAPResultNoSuchAttribute:             "NoSuchAttribute",
	goldap.LDAPResultUndefinedAttributeType:      "UndefinedAttributeType",
	goldap.LDAPResultInappropriateMatching:       "InappropriateMatching",
	goldap.LDAPResultConstraintViolation:         "ConstraintViolation",
	goldap.LDAPResultAttributeOrValueExists:      "AttributeOrValueExists",
	goldap.LDAPResultInvalidAttributeSyntax:      "InvalidAttributeSyntax",
	goldap.LDAPResultNoSuchObject:                "NoSuchObject",
	goldap.LDAPResultAliasProblem:                "AliasProblem",
	goldap.LDAPResultInvalidDNSyntax:             "InvalidDNSyntax",
	goldap.LDAPResultInappropriateAuthentication: "InappropriateAuthentication",
	goldap.LDAPResultInvalidCredentials:          "InvalidCredentials",
	goldap.LDAPResultInsufficientAccessRights:    "InsufficientAccessRights",
	goldap.LDAPResultBusy:                        "Busy",
	goldap.LDAPResultUnavailable:                 "Unavailable",
	goldap.LDAPResultUnwillingToPerform:          "UnwillingToPerform",
	goldap.LDAPResultLoopDetect:                  "LoopDetect",
	goldap.LDAPResultNamingViolation:             "NamingViolation",
	goldap.LDAPResultObjectClassViolation:        "ObjectClassViolation",
	goldap.LDAPResultNotAllowedOnNonLeaf:         "NotAllowedOnNonLeaf",
	goldap.LDAPResultNotAllowedOnRDN:             "NotAllowedOnRDN",
	goldap.LDAPResultEntryAlreadyExists:          "EntryAlreadyExists",
	goldap.LDAPResultObjectClassModsProhibited:   "ObjectClassModsProhibited",
	goldap.LDAPResultAffectsMultipleDSAs:         "AffectsMultipleDSAs",
	goldap.LDAPResultOther:                       "Other",
	CodeNetwork:                                  "Network",
	CodeFilterCompile:                            "FilterSyntax",
}

// nameFor returns the net-ldap error-class name for code, falling back to the
// go-ldap description with its spaces stripped, then to "Error".
func nameFor(code uint16) string {
	if n, ok := codeName[code]; ok {
		return n
	}
	if desc, ok := goldap.LDAPResultCodeMap[code]; ok {
		return strings.ReplaceAll(desc, " ", "")
	}
	return "Error"
}

// mapError converts a transport error into an *Error, translating an
// *ldap.Error's result code into the net-ldap error tree. A nil error maps to
// nil. An error that is already an *Error is returned unchanged. Any error that
// is not an *ldap.Error is treated as a connection/network failure.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var already *Error
	if errors.As(err, &already) {
		return already
	}
	var le *goldap.Error
	if errors.As(err, &le) {
		return &Error{Code: le.ResultCode, Name: nameFor(le.ResultCode), Message: cleanMessage(le), cause: err}
	}
	return &Error{Code: CodeNetwork, Name: "Network", Message: err.Error(), cause: err}
}

// cleanMessage returns the human-readable detail of an *ldap.Error, preferring
// the wrapped underlying error's message and falling back to the code's
// description.
func cleanMessage(le *goldap.Error) string {
	if le.Err != nil {
		return le.Err.Error()
	}
	if desc, ok := goldap.LDAPResultCodeMap[le.ResultCode]; ok {
		return desc
	}
	return ""
}
