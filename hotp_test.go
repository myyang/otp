package otp

import "testing"

func Test6DigitHOTP(t *testing.T) {
	h := NewHOTP()
	opt := New6DisigtHOTPOpts("IssuerFor6", "AccountFor6")
	fkey := "Fakekey1key2key3"

	r, err := h.Generate(1, fkey, opt)
	if err != nil {
		t.FailNow()
	}

	tests := []struct {
		Count  int64
		Exp    bool
		Key    string
		Opt    CryptorOpts
		ErrStr string
	}{
		{1, true, fkey, opt, "Positive verify fail: 1"},
		{2, false, fkey, opt, "Wrong counter verify fail"},
		{1, false, "wrongkey", opt, "Wrong key verify fail"},
		{1, false, fkey, New6DisigtHOTPOpts("user6", "AccountFor6"), "Wrong Issuer verify fail"},
		{1, false, fkey, New6DisigtHOTPOpts("IssuerFor6", "user6"), "Wrong account verify fail"},
		{3, false, "wrong key", New6DisigtHOTPOpts("issuer6", "user6"), "All wrong verify fail"},
	}

	for _, v := range tests {
		if h.Verify(r, v.Count, v.Key, v.Opt) != v.Exp {
			t.Error(v.ErrStr)
		}
	}
}

func Test8DigitHOTP(t *testing.T) {
	h := NewHOTP()
	opt := New8DisigtHOTPOpts("IssuerFor8", "AccountFor8")
	fkey := "FakekeyFor8"

	r, err := h.Generate(0, fkey, opt)
	if err != nil {
		t.FailNow()
	}

	tests := []struct {
		Count  int64
		Exp    bool
		Key    string
		Opt    CryptorOpts
		ErrStr string
	}{
		{0, true, fkey, opt, "Positive verify fail: 0"},
		{2, false, fkey, opt, "Wrong counter verify fail"},
		{0, false, "wrongkey", opt, "Wrong key verify fail"},
		{0, false, fkey, New8DisigtHOTPOpts("user8", "AccountFor8"), "Wrong Issuer verify fail"},
		{0, false, fkey, New8DisigtHOTPOpts("IssuerFor8", "user8"), "Wrong account verify fail"},
		{3, false, "wrong key", New8DisigtHOTPOpts("issuer8", "user8"), "All wrong verify fail"},
	}

	for _, v := range tests {
		if h.Verify(r, v.Count, v.Key, v.Opt) != v.Exp {
			t.Error(v.ErrStr)
		}
	}
}

func Benchmark8DigitHOTP(b *testing.B) {
	h := NewHOTP()
	opt := New8DisigtHOTPOpts("IssuerFor8", "AccountFor8")
	fkey := "FakekeyFor8"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Generate(int64(i), fkey, opt)
	}
}
