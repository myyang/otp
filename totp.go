package otp

import (
	"crypto/sha1"
	"crypto/subtle"
)

// New6DisigtTOTPOpts return 6 digits TOTP options
// unixtime is unix timestamp, both unixtime and period are in second presicion
func New6DisigtTOTPOpts(issuer, account string, unixtime, period int64) CryptorOpts {
	opt, _ := NewCustomTOTPOpts(issuer, account, sha1.New, 6, DefaultMsg, unixtime, period)
	return opt
}

// New8DisigtTOTPOpts return 8 digits TOTP options
func New8DisigtTOTPOpts(issuer, account string, unixtime, period int64) CryptorOpts {
	opt, _ := NewCustomTOTPOpts(issuer, account, sha1.New, 8, DefaultMsg, unixtime, period)
	return opt
}

// NewTOTP return TOTP cryptor
func NewTOTP() *TOTP {
	t := &TOTP{}
	t.initHOTP()
	return t
}

// TOTP algorithm
type TOTP struct {
	hotp *HOTP
}

func (t *TOTP) initHOTP() {
	t.hotp = &HOTP{}
}

// Generate TOTP with given timeframe
func (t *TOTP) Generate(timeframe int64, key string, opts CryptorOpts) (string, error) {
	c := (timeframe - opts.UnixTime) / opts.Period
	return t.hotp.Generate(c, key, opts)
}

// Verify given TOTP code
func (t *TOTP) Verify(code string, timeframe int64, key string, opts CryptorOpts) bool {
	exp, err := t.Generate(timeframe, key, opts)
	if err != nil {
		return false
	}

	if len(exp) == len(code) && subtle.ConstantTimeCompare([]byte(code), []byte(exp)) == 1 {
		return true
	}
	return false
}
