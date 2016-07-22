package otp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
)

// Copy pattern from https://golang.org/pkg/crypto/
// Use a cryptor which implement functions and
// cryptor option which stores customizable params

// Cryptor define functions used by HOTP/TOTP
type Cryptor interface {
	Generate(msg []byte, opts CryptorOpts) []byte
	Verify(val, exp []byte, opts CryptorOpts) bool
}

// MessageFn define provides customizable function to pass message to hash fun
type MessageFn func(int64, CryptorOpts) ([]byte, error)

// CryptorOpts defines customizable variables
type CryptorOpts struct {
	// Issuer and AccountName for distinct
	Issuer      string
	AccountName string
	Algo        func() hash.Hash
	Digits      int
	MsgFn       MessageFn
	UnixTime    int64
	Period      int64
}

// DefaultMsg produce message byte with format "AccountName@Issuer-count"
// and encode with base64
func DefaultMsg(count int64, c CryptorOpts) ([]byte, error) {
	// simple produce
	src := []byte(fmt.Sprintf("%v@%v-%v", c.Issuer, c.AccountName, count))
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return dst, nil
}

// MessageByte generates message bytes with given count
func (c *CryptorOpts) MessageByte(count int64) ([]byte, error) {
	return c.MsgFn(count, *c)
}

func newCustomCryptorOpts(
	issuer, account string, fn func() hash.Hash,
	digits int, msgFn MessageFn, unixtime, period int64) (CryptorOpts, error) {
	if issuer == "" {
		return CryptorOpts{}, ErrEmptyIssuer
	}
	if account == "" {
		return CryptorOpts{}, ErrEmptyAccountName
	}
	if digits > 19 || digits < 1 {
		return CryptorOpts{}, ErrInvalidDigits
	}
	return CryptorOpts{
		Issuer: issuer, AccountName: account, Algo: fn,
		Digits: digits, MsgFn: msgFn, UnixTime: unixtime, Period: period}, nil
}

// NewCustomHOTPOpts return new HOTP options
func NewCustomHOTPOpts(
	issuer, account string, hashfn func() hash.Hash,
	digit int, msg MessageFn) (CryptorOpts, error) {
	return newCustomCryptorOpts(issuer, account, hashfn, digit, msg, 0, 0)
}

// NewCustomTOTPOpts return new HOTP options
func NewCustomTOTPOpts(
	issuer, account string, hashfn func() hash.Hash,
	digit int, msg MessageFn, unixtime, period int64) (CryptorOpts, error) {
	return newCustomCryptorOpts(issuer, account, hashfn, digit, msg, unixtime, period)
}

// Errors
var (
	ErrInvalidDigits    = errors.New("Digits should be between 0 and 19")
	ErrEmptyIssuer      = errors.New("Empty Issuer")
	ErrEmptyAccountName = errors.New("Empty AccountName")
)
