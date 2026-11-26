package openvpn

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestKnownDirectivesCoverTestdata checks that every directive used in the
// fixtures, golden files and reference configs is a known directive, so
// the allowlist rejects nothing that real provider files and TunnelDeck's
// own rendered configs use.
func TestKnownDirectivesCoverTestdata(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob testdata: %v (%d files)", err, len(files))
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			for _, name := range directivesOf(t, readTestdata(t, filepath.Base(path))) {
				if !knownDirectives[name] {
					t.Errorf("directive %q is not in knownDirectives", name)
				}
			}
		})
	}
}

// TestKnownDirectivesCoverHandlers checks that every directive the
// importer maps to a field is known.
func TestKnownDirectivesCoverHandlers(t *testing.T) {
	for name := range directiveHandlers {
		if !knownDirectives[name] {
			t.Errorf("handled directive %q is not in knownDirectives", name)
		}
	}
}

// directivesOf returns the names of the directives of a config text
// outside inline blocks.
func directivesOf(t *testing.T, text string) []string {
	t.Helper()
	var names []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		if match := blockOpener.FindStringSubmatch(strings.TrimSpace(lines[i])); match != nil {
			i = blockEnd(lines, i, match[1])
			if i < 0 {
				t.Fatalf("inline block <%s> is not closed", match[1])
			}
			continue
		}
		if d, status, _ := readLine(lines[i]); status == lineKept {
			names = append(names, d.name)
		}
	}
	return names
}

func TestKnownDirectivesAreValidNames(t *testing.T) {
	for name := range knownDirectives {
		if !directiveName.MatchString(name) {
			t.Errorf("%q is not a valid directive name", name)
		}
	}
}
