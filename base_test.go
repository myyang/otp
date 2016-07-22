package otp

import (
	"crypto/sha1"
	"testing"
)

func TestCryptorOpts(t *testing.T) {
	tests := []struct {
		Issuer  string
		Account string
		Digits  int
		Unix    int64
		Period  int64
		ErrStr  string
	}{
		{"Issuer", "Account", 20, 0, 20, "Invalid len: >19 should be check"},
		{"Issuer", "Account", -2, 0, 20, "Invalid len: <1 should be check"},
		{"Issuer", "Account", 0, 0, 20, "Invalid len: <1 should be check"},
		{"", "Account", 8, 0, 20, "Empty Issuer should be check"},
		{"Issuer", "", 8, 0, 20, "Empty Account should be check"},
	}
	for _, v := range tests {
		_, err := newCustomCryptorOpts(v.Issuer, v.Account, sha1.New, v.Digits, DefaultMsg, v.Unix, v.Period)
		if err == nil {
			t.Error(v.ErrStr)
		}
	}
}

func BenchmarkCryptOpts(b *testing.B) {
	t, l := []struct {
		Issuer  string
		Account string
		Digits  int
		Unix    int64
		Period  int64
		ErrStr  string
	}{
		{"Issuer", "Account", 20, 0, 20, "Invalid len: >19 should be check"},
		{"Issuer", "Account", -2, 0, 20, "Invalid len: <1 should be check"},
		{"Issuer", "Account", 0, 0, 20, "Invalid len: <1 should be check"},
		{"", "Account", 8, 0, 20, "Empty Issuer should be check"},
		{"Issuer", "", 8, 0, 20, "Empty Account should be check"},
	}, 5
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		newCustomCryptorOpts(t[i%l].Issuer, t[i%l].Account, sha1.New, t[i%l].Digits, DefaultMsg, t[i%l].Unix, t[i%l].Period)
	}
}
