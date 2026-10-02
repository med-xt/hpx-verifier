// Package verify is an independent implementation of hpx/1 verification.
//
// It is written from docs/spec/record-format.md rather than from the JavaScript,
// and it is validated against the published conformance vectors. That is the
// point of it: a specification that has only ever been implemented once has not
// been tested, and a verifier an auditor cannot run without trusting us is not
// a verifier.
//
// This file is canonical encoding, which is where interoperability is won or
// lost. Two systems that have never communicated must produce byte-identical
// output for identical facts or no signature crosses an organisational boundary.
package verify

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize renders a decoded JSON value in canonical form.
//
// Decode input with a json.Decoder that has UseNumber set. Without it the
// standard library turns every number into a float64 and the original text is
// gone, which is survivable here only because we reformat anyway, but it hides
// integer overflow and makes failures hard to read.
func Canonicalize(v any) (string, error) {
	var b strings.Builder
	if err := write(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func write(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		b.WriteString(jsString(t))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return fmt.Errorf("unparseable number %q: %w", t.String(), err)
		}
		s, err := jsNumber(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := jsNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []any:
		// Order is meaning. Arrays are never sorted.
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsString(k))
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize %T", v)
	}
	return nil
}

// Keys sort ascending by UTF-16 code unit, which is not the same as Go's native
// byte-wise ordering over UTF-8. The two agree for everything in the Basic
// Multilingual Plane and disagree above it, because a supplementary character
// becomes a surrogate pair in the D800 to DFFF range and therefore sorts before
// U+E000 to U+FFFF rather than after. No hpx/1 key is non-ASCII today. An
// implementation that only works because of that fact breaks the first time the
// schema extends, which is exactly the sort of latent divergence that is
// invisible until two organisations fail to verify each other's records.
func sortUTF16(keys []string) {
	type pair struct {
		s  string
		cu []uint16
	}
	ps := make([]pair, len(keys))
	for i, k := range keys {
		ps[i] = pair{k, utf16.Encode([]rune(k))}
	}
	// Insertion sort: key counts here are small and bounded by the schema.
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && lessCU(ps[j].cu, ps[j-1].cu); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
	for i := range ps {
		keys[i] = ps[i].s
	}
}

func lessCU(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// jsString applies JSON string escaping using the shortest valid escape.
//
// Three things the Go standard library does that would break interoperability
// here, and which this avoids. It escapes <, > and & for HTML safety. It escapes
// U+2028 and U+2029. And it offers no way to turn either off through Marshal.
// None of those appear in ECMAScript JSON.stringify output, so a record encoded
// with encoding/json would not match one encoded in the reference implementation.
//
// The forward slash is deliberately not escaped. Escaping it is legal JSON and
// produces different bytes, which is the only thing that matters.
func jsString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// jsNumber reproduces ECMAScript Number::toString, which is what the reference
// implementation emits and therefore what the digests were computed over.
//
// Go's strconv does shortest round-trip correctly but chooses between fixed and
// exponential notation on different thresholds. Go renders 1e20 as "1e+20"
// where ECMAScript renders it "100000000000000000000". A verifier that used
// strconv directly would reject every record containing a large number, and the
// failure would look like tampering rather than a formatting disagreement.
//
// The rule, from the specification of Number::toString: let the shortest
// round-trip decimal be s digits with value s x 10^(n-k), where k is the digit
// count. Use fixed notation when the decimal point falls within the digits or
// just after them up to 21 places, use leading-zero notation down to 10^-6, and
// use exponential notation outside that band.
func jsNumber(f float64) (string, error) {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("non-finite number is not serialisable")
	}
	// Negative zero serialises as "0". The comparison catches both zeroes.
	if f == 0 {
		return "0", nil
	}

	neg := f < 0
	if neg {
		f = -f
	}

	// Shortest round-trip in scientific form gives both the digits and the
	// exponent without having to decide on notation first.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	ei := strings.IndexByte(sci, 'e')
	mant := sci[:ei]
	exp, err := strconv.Atoi(sci[ei+1:])
	if err != nil {
		return "", fmt.Errorf("unreadable exponent in %q: %w", sci, err)
	}

	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}

// Decode parses JSON preserving number text, which is what every entry point
// into this package should use.
func Decode(data []byte) (any, error) {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
