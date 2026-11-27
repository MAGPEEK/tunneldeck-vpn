package web

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandlerServesFilesAndFallsBackToIndex(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":    {Data: []byte("<html>index</html>")},
		"assets/app.js": {Data: []byte("console.log('app')")},
	}
	tests := []struct {
		name     string
		path     string
		wantCode int
		wantBody string
	}{
		{name: "root serves index", path: "/", wantCode: http.StatusOK, wantBody: "<html>index</html>"},
		{name: "asset is served", path: "/assets/app.js", wantCode: http.StatusOK, wantBody: "console.log('app')"},
		{name: "client route falls back to index", path: "/profiles/42", wantCode: http.StatusOK, wantBody: "<html>index</html>"},
		{name: "directory falls back to index", path: "/assets/", wantCode: http.StatusOK, wantBody: "<html>index</html>"},
	}
	handler := NewHandler(assets)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestHandlerReportsMissingBuild(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(fstest.MapFS{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "not built") {
		t.Fatalf("body = %q, want hint about missing build", rec.Body.String())
	}
}

func TestEmbeddedHandlerResponds(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 200 (built) or 503 (not built)", rec.Code)
	}
}

// scriptElement captures a script's attributes and content.
var scriptElement = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

// inlineMarkup matches the rest of what the Content-Security-Policy of
// SPEC §8 blocks: <style> elements, style attributes, inline event handlers
// and javascript: URLs.
var inlineMarkup = regexp.MustCompile(`(?i)<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:`)

// inlineCode returns the first inline code in html, or "".
func inlineCode(html string) string {
	for _, script := range scriptElement.FindAllStringSubmatch(html, -1) {
		if !strings.Contains(strings.ToLower(script[1]), "src=") || strings.TrimSpace(script[2]) != "" {
			return script[0]
		}
	}
	return inlineMarkup.FindString(html)
}

// TestBuiltIndexHasNoInlineCode guards the Content-Security-Policy: the
// built index.html must load everything from files. Skipped before the
// frontend is built.
func TestBuiltIndexHasNoInlineCode(t *testing.T) {
	index, err := fs.ReadFile(dist, "dist/"+indexFile)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("web UI not built")
	}
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if found := inlineCode(string(index)); found != "" {
		t.Fatalf("index.html has inline code the CSP blocks: %q", found)
	}
}

func TestInlineCode(t *testing.T) {
	tests := []struct {
		html   string
		inline bool
	}{
		{`<script type="module" crossorigin src="/assets/index.js"></script>`, false},
		{`<link rel="stylesheet" crossorigin href="/assets/index.css">`, false},
		{`<meta name="theme-color" content="#1f63c9" />`, false},
		{`<script>alert(1)</script>`, true},
		{`<script type="module">import "/a.js"</script>`, true},
		{`<script src="/a.js">alert(1)</script>`, true},
		{`<style>body{}</style>`, true},
		{`<div style="color:red">`, true},
		{`<body onload="x()">`, true},
		{`<a href="javascript:x()">`, true},
	}
	for _, tt := range tests {
		if got := inlineCode(tt.html) != ""; got != tt.inline {
			t.Errorf("%s: inline = %v, want %v", tt.html, got, tt.inline)
		}
	}
}

func TestHandlerServesIconFilesWithContentType(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":           {Data: []byte("<html>index</html>")},
		"favicon.ico":          {Data: []byte("ico")},
		"manifest.webmanifest": {Data: []byte("{}")},
		"icon.svg":             {Data: []byte("<svg/>")},
		"icon-192.png":         {Data: []byte("png")},
	}
	tests := []struct {
		path     string
		wantType string
		wantBody string
	}{
		{path: "/favicon.ico", wantType: "image/x-icon", wantBody: "ico"},
		{path: "/manifest.webmanifest", wantType: "application/manifest+json", wantBody: "{}"},
		{path: "/icon.svg", wantType: "image/svg+xml", wantBody: "<svg/>"},
		{path: "/icon-192.png", wantType: "image/png", wantBody: "png"},
	}
	handler := NewHandler(assets)
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if got := rec.Header().Get("Content-Type"); got != tt.wantType {
				t.Fatalf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}
