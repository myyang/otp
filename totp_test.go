package otp

import "testing"
import "time"

func Test6DigitTOTP(t *testing.T) {
	h := NewTOTP()
	tf := time.Now().Unix()
	opt := New6DisigtTOTPOpts("IssuerFor6", "AccountFor6", tf, 300)
	fkey := "Fakekey1key2key3"

	r, err := h.Generate(tf+30, fkey, opt)
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
		{tf, true, fkey, opt, "Positive verify fail: same time"},
		{tf + 298, true, fkey, opt, "Positive verify fail: tf + 298"},
		{tf + 301, false, fkey, opt, "Wrong timeframe verify fail"},
		{tf, false, "wrongkey", opt, "Wrong key verify fail"},
		{tf, false, fkey, New6DisigtTOTPOpts("user6", "AccountFor6", 0, 300), "Wrong Issuer verify fail"},
		{tf, false, fkey, New6DisigtTOTPOpts("IssuerFor6", "user6", 0, 300), "Wrong account verify fail"},
		{tf, false, fkey, New6DisigtTOTPOpts("IssuerFor6", "AccountFor6", 387, 300), "Wrong UinxTime verify fail"},
		{tf, false, fkey, New6DisigtTOTPOpts("IssuerFor6", "AccountFor6", 0, 800), "Wrong Period verify fail"},
		{tf, false, "wrong key", New6DisigtTOTPOpts("issuer6", "user6", 265, 700), "All wrong verify fail"},
	}

	for _, v := range tests {
		if h.Verify(r, v.Count, v.Key, v.Opt) != v.Exp {
			r2, _ := h.Generate(v.Count, v.Key, v.Opt)
			t.Errorf("Err: %v, exp: %v, got: %v\n", v.ErrStr, r, r2)
		}
	}
}

func Test8DigitTOTP(t *testing.T) {
	h := NewTOTP()
	tf := time.Now().Unix()
	opt := New8DisigtTOTPOpts("IssuerFor8", "AccountFor8", tf, 300)
	fkey := "Fakekey1key2key3"

	r, err := h.Generate(tf+30, fkey, opt)
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
		{tf, true, fkey, opt, "Positive verify fail: same time"},
		{tf + 298, true, fkey, opt, "Positive verify fail: tf + 298"},
		{tf + 301, false, fkey, opt, "Wrong timeframe verify fail"},
		{tf, false, "wrongkey", opt, "Wrong key verify fail"},
		{tf, false, fkey, New8DisigtTOTPOpts("user8", "AccountFor8", 0, 300), "Wrong Issuer verify fail"},
		{tf, false, fkey, New8DisigtTOTPOpts("IssuerFor8", "user8", 0, 300), "Wrong account verify fail"},
		{tf, false, fkey, New8DisigtTOTPOpts("IssuerFor8", "AccountFor8", 387, 300), "Wrong UinxTime verify fail"},
		{tf, false, fkey, New8DisigtTOTPOpts("IssuerFor8", "AccountFor8", 0, 800), "Wrong Period verify fail"},
		{tf, false, "wrong key", New8DisigtTOTPOpts("issuer8", "user8", 265, 700), "All wrong verify fail"},
	}

	for _, v := range tests {
		if h.Verify(r, v.Count, v.Key, v.Opt) != v.Exp {
			r2, _ := h.Generate(v.Count, v.Key, v.Opt)
			t.Errorf("Err: %v, exp: %v, got: %v\n", v.ErrStr, r, r2)
		}
	}
}

func Benchmark8DigitTOTP(b *testing.B) {
	h := NewTOTP()
	tf := time.Now().Unix()
	opt := New8DisigtTOTPOpts("IssuerFor8", "AccountFor8", tf, 300)
	fkey := "Fakekey1key2key3"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Generate(int64(i), fkey, opt)
	}
}
