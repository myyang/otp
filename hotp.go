package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"math"
	"strconv"
)

// New6DisigtHOTPOpts return 6 digits options with SHA1 hash
func New6DisigtHOTPOpts(issuer, account string) CryptorOpts {
	opt, _ := NewCustomHOTPOpts(issuer, account, sha1.New, 6, DefaultMsg)
	return opt
}

// New8DisigtHOTPOpts return 8 digits options with SHA1 hash
func New8DisigtHOTPOpts(issuer, account string) CryptorOpts {
	opt, _ := NewCustomHOTPOpts(issuer, account, sha1.New, 8, DefaultMsg)
	return opt
}

// NewHOTP return default HOTP cryptor
func NewHOTP() *HOTP { return &HOTP{} }

// HOTP algorithm
type HOTP struct{}

func (h *HOTP) generate(count int64, key []byte, opts CryptorOpts) (int, error) {
	msg, err := opts.MessageByte(count)
	if err != nil {
		return -1, err
	}
	c := hmac.New(opts.Algo, key)
	c.Write(msg)
	hv := c.Sum(nil)

	// hotp implement https://tools.ietf.org/html/rfc4226#section-5.4
	offset := hv[len(hv)-1] & 0xf
	value := int64(((int(hv[offset]) & 0x7f) << 24) |
		((int(hv[offset+1]) & 0xff) << 16) |
		((int(hv[offset+2]) & 0xff) << 8) |
		(int(hv[offset+3]) & 0xff))
	value %= int64(math.Pow10(opts.Digits))

	return int(value), nil
}

// Generate hotp code by given msg
func (h *HOTP) Generate(count int64, key string, opts CryptorOpts) (string, error) {
	c, err := h.generate(count, []byte(key), opts)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(c), nil
}

// Verify hotp, pass same params as Generate but prepending the code to verify
func (h *HOTP) Verify(code string, count int64, key string, opts CryptorOpts) bool {
	exp, err := h.Generate(count, key, opts)
	if err != nil {
		return false
	}
	if len(exp) == len(code) && subtle.ConstantTimeCompare([]byte(code), []byte(exp)) == 1 {
		return true
	}
	return false
}
