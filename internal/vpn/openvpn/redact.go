package openvpn

import (
	"slices"
	"strings"
)

// hiddenValue replaces text that could reveal a credential.
const hiddenValue = "(hidden)"

// redactor hides credentials in directive names and file names that are
// quoted back in warnings and validation errors. A credential typed on a
// line of its own parses as a directive whose name is the credential.
type redactor struct {
	credentials []string
}

// newRedactor returns a redactor for the given credentials; empty ones are
// ignored.
func newRedactor(credentials ...string) redactor {
	var r redactor
	for _, credential := range credentials {
		if strings.TrimSpace(credential) != "" {
			r.credentials = append(r.credentials, credential)
		}
	}
	return r
}

// hides reports whether text could reveal a credential: it equals one, is
// part of one (a password with spaces splits into several tokens) or
// contains one.
func (r redactor) hides(text string) bool {
	if text == "" {
		return false
	}
	return slices.ContainsFunc(r.credentials, func(credential string) bool {
		return strings.Contains(credential, text) || strings.Contains(text, credential)
	})
}

// warning returns w with its directive and file hidden, also inside the
// message, when they could reveal a credential.
func (r redactor) warning(w Warning) Warning {
	for _, field := range []*string{&w.Directive, &w.File} {
		if r.hides(*field) {
			w.Message = strings.ReplaceAll(w.Message, *field, hiddenValue)
			*field = hiddenValue
		}
	}
	return w
}

// warnings applies warning to each element of ws in place and returns ws.
func (r redactor) warnings(ws []Warning) []Warning {
	for i, w := range ws {
		ws[i] = r.warning(w)
	}
	return ws
}
