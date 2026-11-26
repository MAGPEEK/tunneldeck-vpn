package web

import (
	"net/http"
	"net/http/httptest"
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
