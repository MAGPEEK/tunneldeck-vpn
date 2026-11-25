package openvpn

import (
	"errors"
	"regexp"
	"strings"
)

// maxLineLength is the longest config line OpenVPN accepts: a line of 256
// characters fails with "Maximum option line length (256) exceeded".
// Extra options must stay below it, so lines of maxLineLength or more are
// rejected.
const maxLineLength = 255

// directive is one parsed config line: the option name and its parameters.
type directive struct {
	name string
	args []string
}

// directiveName matches OpenVPN option names, which are all lower case.
var directiveName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// bareToken matches parameters that need no quoting.
var bareToken = regexp.MustCompile(`^[A-Za-z0-9._:/,=+@%-]+$`)

var (
	errUnterminatedQuote = errors.New("unterminated quote")
	errBadBackslash      = errors.New("bad backslash usage")
)

// String renders d as one config line that OpenVPN parses back into the
// same name and parameters.
func (d directive) String() string {
	tokens := make([]string, 0, len(d.args)+1)
	tokens = append(tokens, d.name)
	for _, arg := range d.args {
		tokens = append(tokens, quote(arg))
	}
	return strings.Join(tokens, " ")
}

// arg returns parameter i, or "" when it is missing.
func (d directive) arg(i int) string {
	if i < len(d.args) {
		return d.args[i]
	}
	return ""
}

// quote returns token unchanged when it is safe bare, otherwise in double
// quotes with backslash and double quote escaped. Tokens starting with '#'
// or ';', which OpenVPN would read as a comment, are never bare.
func quote(token string) string {
	if bareToken.MatchString(token) {
		return token
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(token)
	return `"` + escaped + `"`
}

// parseDirective tokenizes line and strips one leading "--" from the option
// name, as OpenVPN does for config files. ok is false for blank and comment
// lines.
func parseDirective(line string) (d directive, ok bool, err error) {
	tokens, err := tokenize(line)
	if err != nil || len(tokens) == 0 {
		return directive{}, false, err
	}
	name := tokens[0]
	if len(name) > 2 && strings.HasPrefix(name, "--") {
		name = name[2:]
	}
	return directive{name: name, args: tokens[1:]}, true, nil
}

// tokenizer states, mirroring OpenVPN's parse_line().
type tokenState int

const (
	stateInitial tokenState = iota
	stateUnquoted
	stateDoubleQuoted
	stateSingleQuoted
)

// tokenize splits line into parameters the way OpenVPN's parse_line() does:
// whitespace separates tokens; "..." allows the escapes \\, \" and \<space>;
// '...' is literal; outside single quotes a backslash escapes \, " or
// whitespace and any other escape is an error; '#' or ';' where a token
// would start begins a comment.
func tokenize(line string) ([]string, error) {
	t := tokenizer{}
	for i := 0; i < len(line); i++ {
		if t.feed(line[i]) {
			break
		}
		if t.err != nil {
			return nil, t.err
		}
	}
	return t.finish()
}

type tokenizer struct {
	tokens    []string
	current   strings.Builder
	state     tokenState
	backslash bool
	err       error
}

// feed consumes one byte and reports whether a comment started.
func (t *tokenizer) feed(c byte) (comment bool) {
	if t.state == stateInitial && isComment(c) {
		return true
	}
	if c == '\\' && !t.backslash && t.state != stateSingleQuoted {
		t.backslash = true
		return false
	}
	escaped := t.backslash
	t.backslash = false
	if escaped && c != '\\' && c != '"' && !isSpace(c) {
		t.err = errBadBackslash
		return false
	}
	switch t.state {
	case stateInitial:
		t.startToken(c)
	case stateUnquoted:
		t.continueUnquoted(c, escaped)
	case stateDoubleQuoted:
		t.continueQuoted(c, escaped, '"')
	case stateSingleQuoted:
		t.continueQuoted(c, false, '\'')
	}
	return false
}

// startToken mirrors OpenVPN, where a quote opens a quoted token even right
// after a backslash.
func (t *tokenizer) startToken(c byte) {
	switch {
	case isSpace(c):
	case c == '"':
		t.state = stateDoubleQuoted
	case c == '\'':
		t.state = stateSingleQuoted
	default:
		t.current.WriteByte(c)
		t.state = stateUnquoted
	}
}

func (t *tokenizer) continueUnquoted(c byte, escaped bool) {
	if isSpace(c) && !escaped {
		t.endToken()
		return
	}
	t.current.WriteByte(c)
}

func (t *tokenizer) continueQuoted(c byte, escaped bool, closing byte) {
	if c == closing && !escaped {
		t.endToken()
		return
	}
	t.current.WriteByte(c)
}

func (t *tokenizer) endToken() {
	t.tokens = append(t.tokens, t.current.String())
	t.current.Reset()
	t.state = stateInitial
}

func (t *tokenizer) finish() ([]string, error) {
	switch t.state {
	case stateDoubleQuoted, stateSingleQuoted:
		return nil, errUnterminatedQuote
	case stateUnquoted:
		t.endToken()
	}
	return t.tokens, nil
}

func isComment(c byte) bool { return c == '#' || c == ';' }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// hasControlCharacter reports whether s contains an ASCII control character
// other than tab, for example NUL, CR or LF.
func hasControlCharacter(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return (r < 0x20 && r != '\t') || r == 0x7f
	})
}
