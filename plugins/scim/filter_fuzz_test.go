package scim

import "testing"

// Standing fuzz coverage for the SCIM filter parser. This target found no
// defect; it exists so a future edit to the scanner cannot quietly introduce
// one.
//
// ParseFilter is a hand-rolled scanner over the `filter` query parameter on
// GET /scim/v2/Users (users.go:622) and GET /scim/v2/Groups (groups.go:197).
// It is NOT pre-auth: p.authenticate(..., scimRead) runs first, at
// users.go:615 and groups.go:190, so the input here is reachable by any
// client holding a SCIM read token for the org — a provisioning integration,
// or anyone who has obtained its token. That is still an attacker-controlled
// string arriving from off the wire, and it is the only bespoke parser in the
// module that one reaches.
//
// Two invariants are pinned here:
//
//  1. ParseFilter returns EXACTLY ONE of (filter, error). Both call sites
//     nil-check the parse — users.go:673 is `if parsed == nil || userMatches
//     Filter(...)` and groups.go:229 is `if parsed != nil {` — so a (nil, nil)
//     return does not crash. It does something quieter and worse: the filter
//     is SILENTLY DROPPED and the endpoint returns the org's entire user or
//     group list. A provisioning client that asked `userName eq "x"` and got
//     rows back reads that as "x exists", so a parser bug becomes a wrong
//     answer to an existence question and a full directory disclosure in one
//     step. A (non-nil, non-nil) return is the mirror: a filter the parser
//     rejected still gets evaluated.
//  2. A filter it accepts is evaluable — Matches with a resolve callback that
//     touches every atom's value must not panic on any accepted parse.
//
// The AND loop in parseFilter must also always make progress; a seed that
// caused it to spin would hang here rather than in production.
//
// Unlike the signature-gated targets in bearer/asymjwt/ssosaml, every branch
// asserted here is genuinely reachable by the mutator: ParseFilter takes the
// raw string with no cryptographic gate in front of it, so a regression that
// broke either invariant would actually be found by `-fuzz`, not merely
// tripped over by a later human. The legitimate accept path is pinned
// separately by TestParseFilter_AcceptsAnd in scim_test.go, so a "fix" that
// made ParseFilter reject everything would fail there rather than turn this
// target trivially green.
func FuzzParseFilter(f *testing.F) {
	seeds := []string{
		// Vectors already asserted in scim_test.go.
		`a eq "x" or b eq "y"`,
		`userName sw "al" and active eq true`,
		"userName eq `alice`",
		// Numeric edges around readNumber's strconv.ParseInt.
		`n eq -9223372036854775808`,
		`n eq 9223372036854775807`,
		`n eq 99999999999999999999999`,
		`n eq -`,
		// String scanner edges.
		`x eq "\q"`,
		`x eq "unterminated`,
		`x eq "\`,
		"x eq \"nul\x00inside\"",
		`x co "\n\t\r\\\/\""`,
		// Keyword / operator edges.
		`and and and`,
		`x pr`,
		`x ew "y"`,
		`andrew eq "x"`,
		`x eq true and(y eq false)`,
		`x eq TRUE`,
		`   `,
		``,
		// Long AND chain, to catch unbounded growth or a stalled loop.
		`a eq "1" and b eq "2" and c eq "3" and d eq "4" and e eq "5" and f eq "6"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		flt, errBody := ParseFilter(in)
		if (flt == nil) == (errBody == nil) {
			t.Fatalf("ParseFilter(%q): exactly one of filter/err must be non-nil (filter=%v err=%v)", in, flt, errBody)
		}
		if errBody != nil {
			if errBody.ScimType != "invalidFilter" {
				t.Fatalf("ParseFilter(%q): rejection must carry scimType invalidFilter, got %q", in, errBody.ScimType)
			}
			return
		}
		if len(flt.Atoms) == 0 {
			t.Fatalf("ParseFilter(%q): accepted a filter with no atoms", in)
		}
		// An accepted filter is one users.go will evaluate against every row it
		// considers. Exercise both value shapes it can be asked for.
		_ = flt.Matches(func(a FilterAtom) bool {
			return a.Value.MatchesString(a.Op, "candidate") || a.Value.MatchesBool(a.Op, true)
		})
	})
}
