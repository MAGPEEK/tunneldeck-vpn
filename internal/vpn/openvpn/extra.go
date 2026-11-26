package openvpn

import (
	"fmt"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
)

// lineStatus is the outcome of reading one config line.
type lineStatus int

const (
	lineBlank   lineStatus = iota // empty or comment only
	lineKept                      // a usable directive
	lineRemoved                   // dropped or rejected, see the verdict
)

// readLine parses one raw config line outside inline blocks. Surrounding
// whitespace, including the CR of CRLF input, is removed. Control
// characters, lines of maxLineLength or more, syntax errors and inline
// block tags are rejected.
func readLine(raw string) (directive, lineStatus, verdict) {
	line := strings.TrimSpace(raw)
	switch {
	case line == "":
		return directive{}, lineBlank, verdict{}
	case hasControlCharacter(line):
		return directive{}, lineRemoved, rejection(CodeInvalidLine, "contains control characters such as NUL, CR or LF")
	case len(line) >= maxLineLength:
		return directive{}, lineRemoved, lineTooLong
	}
	d, ok, err := parseDirective(line)
	switch {
	case err != nil:
		return directive{}, lineRemoved, rejection(CodeInvalidLine, "cannot be parsed: "+err.Error())
	case !ok:
		return directive{}, lineBlank, verdict{}
	case strings.HasPrefix(d.name, "<"):
		return d, lineRemoved, rejection(CodeInlineBlock, "inline blocks are not allowed here; use the profile fields")
	}
	return d, lineKept, verdict{}
}

var lineTooLong = rejection(CodeLineTooLong, fmt.Sprintf("is %d characters or longer", maxLineLength))

func rejection(code, message string) verdict {
	return verdict{code: code, severity: SeverityRejected, message: message}
}

// extraOption is a kept extra option with its 1-based position.
type extraOption struct {
	line      int
	directive directive
}

// extraResult sorts the extra options of a profile into kept, dropped and
// rejected lines.
type extraResult struct {
	kept     []extraOption
	dropped  []Warning
	rejected []Warning
}

// checkExtraOptions applies readLine, the classifier and the line length
// limit to every extra option.
func checkExtraOptions(lines []string) extraResult {
	var result extraResult
	for i, raw := range lines {
		number := i + 1
		d, status, v := readLine(raw)
		if status == lineKept {
			v, status = classifyKept(d)
		}
		switch {
		case status == lineBlank:
		case status == lineKept:
			result.kept = append(result.kept, extraOption{line: number, directive: d})
		case v.rejected():
			result.rejected = append(result.rejected, v.warning(d, number))
		default:
			result.dropped = append(result.dropped, v.warning(d, number))
		}
	}
	return result
}

// classifyKept classifies a parsed directive and checks that its canonical
// form still fits on one config line.
func classifyKept(d directive) (verdict, lineStatus) {
	if v, removed := classify(d); removed {
		return v, lineRemoved
	}
	if len(d.String()) >= maxLineLength {
		return lineTooLong, lineRemoved
	}
	return verdict{}, lineKept
}

// rejectionIssue names the rejected lines for a translated message.
func rejectionIssue(rejected []Warning) domain.FieldIssue {
	lines := make([]string, len(rejected))
	for i, w := range rejected {
		lines[i] = strconv.Itoa(w.Line)
	}
	return domain.Issue("openvpn_extra_options_rejected", "lines", strings.Join(lines, ", "))
}

// describeRejections joins rejected lines into one validation message. Only
// well-formed directive names are quoted, never other submitted text.
func describeRejections(rejected []Warning) string {
	parts := make([]string, 0, len(rejected))
	for _, w := range rejected {
		subject := ""
		if directiveName.MatchString(w.Directive) {
			subject = fmt.Sprintf("%q ", w.Directive)
		}
		parts = append(parts, fmt.Sprintf("line %d: %s%s", w.Line, subject, w.Message))
	}
	return strings.Join(parts, "; ")
}
