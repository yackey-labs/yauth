package scim

import (
	"fmt"
	"strconv"
	"strings"
)

// Minimal SCIM filter parser (RFC 7644 §3.4.2.2 subset).
//
// Supported syntax:
//
//	filter      = expr (SP "and" SP expr)*
//	expr        = attr SP op SP value
//	op          = "eq" / "co" / "sw"
//	value       = quoted-string / boolean / number
//
// Examples:
//
//   - userName eq "alice@acme.com"
//   - displayName co "Alice"
//   - userName sw "a" and active eq true
//
// Unsupported tokens (or, pr, gt, parens, nested attributes like
// emails[type eq "work"].value) are rejected with invalidFilter so
// callers don't silently get incomplete results.
//
// Why hand-rolled? SCIM is the only place yauth-go needs a filter
// language. A general parser-combinator dep would dwarf the actual
// requirement (three operators + AND).

// FilterOp is the comparison operator on a single atom.
type FilterOp int

const (
	// FilterOpEq is exact match, case-insensitive for strings.
	FilterOpEq FilterOp = iota
	// FilterOpCo is substring contains.
	FilterOpCo
	// FilterOpSw is starts-with.
	FilterOpSw
)

// FilterValueKind discriminates between RHS literal types.
type FilterValueKind int

const (
	// FilterValueString is a quoted string literal.
	FilterValueString FilterValueKind = iota
	// FilterValueBool is the bare keyword true/false.
	FilterValueBool
	// FilterValueNumber is an integer literal.
	FilterValueNumber
)

// FilterValue is a parsed RHS literal value.
type FilterValue struct {
	Kind FilterValueKind
	Str  string
	Bool bool
	Num  int64
}

// MatchesString reports whether candidate satisfies (op, value) treating
// the value as a string. Eq is case-insensitive (RFC 7644 §3.4.2.2 —
// caseExact: false default).
func (v FilterValue) MatchesString(op FilterOp, candidate string) bool {
	var needle string
	switch v.Kind {
	case FilterValueString:
		needle = v.Str
	case FilterValueBool:
		if op != FilterOpEq {
			return false
		}
		want := "false"
		if v.Bool {
			want = "true"
		}
		return strings.EqualFold(candidate, want)
	case FilterValueNumber:
		if op != FilterOpEq {
			return false
		}
		return candidate == strconv.FormatInt(v.Num, 10)
	default:
		return false
	}
	c := strings.ToLower(candidate)
	n := strings.ToLower(needle)
	switch op {
	case FilterOpEq:
		return c == n
	case FilterOpCo:
		return strings.Contains(c, n)
	case FilterOpSw:
		return strings.HasPrefix(c, n)
	}
	return false
}

// MatchesBool reports whether candidate satisfies (op, value) treating
// the value as a boolean.
func (v FilterValue) MatchesBool(op FilterOp, candidate bool) bool {
	if op != FilterOpEq {
		return false
	}
	switch v.Kind {
	case FilterValueBool:
		return v.Bool == candidate
	case FilterValueString:
		want := "false"
		if candidate {
			want = "true"
		}
		return strings.EqualFold(v.Str, want)
	}
	return false
}

// FilterAtom is a single matchable predicate.
type FilterAtom struct {
	Attr  string // attribute path, callers downcase before matching
	Op    FilterOp
	Value FilterValue
}

// Filter is a parsed top-level filter — a non-empty list of atoms
// joined by AND.
type Filter struct {
	Atoms []FilterAtom
}

// Matches reports whether the resolve callback returns true for every
// atom (logical AND).
func (f *Filter) Matches(resolve func(FilterAtom) bool) bool {
	for _, a := range f.Atoms {
		if !resolve(a) {
			return false
		}
	}
	return true
}

// ParseFilter parses a SCIM filter string. Returns a SCIM-shaped error
// body (status 400, scimType invalidFilter) on rejection.
func ParseFilter(input string) (*Filter, *ScimErrorBody) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		e := NewScimErrorBody(400, "invalidFilter", "empty filter")
		return nil, &e
	}
	p := &filterParser{src: []byte(trimmed)}
	f, scimErr := p.parseFilter()
	if scimErr != nil {
		return nil, scimErr
	}
	if scimErr := p.expectEOF(); scimErr != nil {
		return nil, scimErr
	}
	return f, nil
}

func invalidFilterErr(detail string) *ScimErrorBody {
	e := NewScimErrorBody(400, "invalidFilter", detail)
	return &e
}

type filterParser struct {
	src []byte
	pos int
}

func (p *filterParser) peek() (byte, bool) {
	if p.pos >= len(p.src) {
		return 0, false
	}
	return p.src[p.pos], true
}

func (p *filterParser) bump() (byte, bool) {
	c, ok := p.peek()
	if !ok {
		return 0, false
	}
	p.pos++
	return c, true
}

func (p *filterParser) skipWS() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' {
			p.pos++
			continue
		}
		break
	}
}

// readIdent reads an identifier [A-Za-z][A-Za-z0-9_.-]*.
func (p *filterParser) readIdent() (string, *ScimErrorBody) {
	p.skipWS()
	start := p.pos
	c, ok := p.peek()
	if !ok || !isAlpha(c) {
		return "", invalidFilterErr("expected attribute name")
	}
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if isAlpha(c) || isDigit(c) || c == '_' || c == '.' || c == '-' {
			p.pos++
			continue
		}
		break
	}
	return string(p.src[start:p.pos]), nil
}

// matchKeyword tries to consume the keyword (case-insensitive). Returns
// true if matched and advanced; false otherwise (no position change).
// The keyword must be terminated by whitespace, '(', or EOF — so `and`
// does not match the start of `andrew`.
func (p *filterParser) matchKeyword(expected string) bool {
	p.skipWS()
	if p.pos+len(expected) > len(p.src) {
		return false
	}
	for i := 0; i < len(expected); i++ {
		if !asciiEqIgnoreCase(p.src[p.pos+i], expected[i]) {
			return false
		}
	}
	if p.pos+len(expected) < len(p.src) {
		next := p.src[p.pos+len(expected)]
		if next != ' ' && next != '\t' && next != '(' {
			return false
		}
	}
	p.pos += len(expected)
	return true
}

func (p *filterParser) readOp() (FilterOp, *ScimErrorBody) {
	p.skipWS()
	start := p.pos
	for p.pos < len(p.src) && isAlpha(p.src[p.pos]) {
		p.pos++
	}
	op := strings.ToLower(string(p.src[start:p.pos]))
	switch op {
	case "eq":
		return FilterOpEq, nil
	case "co":
		return FilterOpCo, nil
	case "sw":
		return FilterOpSw, nil
	case "":
		return 0, invalidFilterErr("missing comparison operator")
	case "ne", "gt", "ge", "lt", "le", "pr", "ew":
		return 0, invalidFilterErr(fmt.Sprintf("operator '%s' is not supported (only eq, co, sw)", op))
	default:
		return 0, invalidFilterErr(fmt.Sprintf("unknown operator: %s", op))
	}
}

func (p *filterParser) readValue() (FilterValue, *ScimErrorBody) {
	p.skipWS()
	c, ok := p.peek()
	if !ok {
		return FilterValue{}, invalidFilterErr("expected quoted string, boolean, or number on RHS")
	}
	switch {
	case c == '"':
		s, err := p.readQuotedString()
		if err != nil {
			return FilterValue{}, err
		}
		return FilterValue{Kind: FilterValueString, Str: s}, nil
	case (c == 't' || c == 'T') && p.matchKeyword("true"):
		return FilterValue{Kind: FilterValueBool, Bool: true}, nil
	case (c == 'f' || c == 'F') && p.matchKeyword("false"):
		return FilterValue{Kind: FilterValueBool, Bool: false}, nil
	case isDigit(c) || c == '-':
		return p.readNumber()
	}
	return FilterValue{}, invalidFilterErr("expected quoted string, boolean, or number on RHS")
}

func (p *filterParser) readQuotedString() (string, *ScimErrorBody) {
	// Consume opening quote.
	c, ok := p.bump()
	if !ok || c != '"' {
		return "", invalidFilterErr("expected opening quote")
	}
	var sb strings.Builder
	for {
		c, ok := p.bump()
		if !ok {
			return "", invalidFilterErr("unterminated string literal")
		}
		switch c {
		case '"':
			return sb.String(), nil
		case '\\':
			esc, ok := p.bump()
			if !ok {
				return "", invalidFilterErr("dangling escape")
			}
			switch esc {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			default:
				return "", invalidFilterErr("unsupported escape sequence")
			}
		default:
			sb.WriteByte(c)
		}
	}
}

func (p *filterParser) readNumber() (FilterValue, *ScimErrorBody) {
	start := p.pos
	if c, ok := p.peek(); ok && c == '-' {
		p.pos++
	}
	for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
		p.pos++
	}
	slice := string(p.src[start:p.pos])
	n, err := strconv.ParseInt(slice, 10, 64)
	if err != nil {
		return FilterValue{}, invalidFilterErr("invalid number: " + slice)
	}
	return FilterValue{Kind: FilterValueNumber, Num: n}, nil
}

func (p *filterParser) parseAtom() (FilterAtom, *ScimErrorBody) {
	attr, err := p.readIdent()
	if err != nil {
		return FilterAtom{}, err
	}
	op, err := p.readOp()
	if err != nil {
		return FilterAtom{}, err
	}
	value, err := p.readValue()
	if err != nil {
		return FilterAtom{}, err
	}
	return FilterAtom{Attr: attr, Op: op, Value: value}, nil
}

func (p *filterParser) parseFilter() (*Filter, *ScimErrorBody) {
	first, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	atoms := []FilterAtom{first}
	for {
		p.skipWS()
		if p.pos >= len(p.src) {
			break
		}
		if p.matchKeyword("and") {
			next, err := p.parseAtom()
			if err != nil {
				return nil, err
			}
			atoms = append(atoms, next)
			continue
		}
		if p.matchKeyword("or") {
			return nil, invalidFilterErr("'or' is not supported — only 'and' joins multiple predicates")
		}
		return nil, invalidFilterErr(fmt.Sprintf("unexpected character at position %d", p.pos))
	}
	return &Filter{Atoms: atoms}, nil
}

func (p *filterParser) expectEOF() *ScimErrorBody {
	p.skipWS()
	if p.pos < len(p.src) {
		return invalidFilterErr(fmt.Sprintf("trailing input at position %d", p.pos))
	}
	return nil
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func asciiEqIgnoreCase(a, b byte) bool {
	if a >= 'A' && a <= 'Z' {
		a += 32
	}
	if b >= 'A' && b <= 'Z' {
		b += 32
	}
	return a == b
}
