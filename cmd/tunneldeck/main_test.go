package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSystemHandlerReturnsVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	systemHandler("1.2.3").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/system", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	var body systemResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Version != "1.2.3" {
		t.Fatalf("version = %q, want 1.2.3", body.Version)
	}
}

func TestRouter(t *testing.T) {
	spa := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("spa"))
	})
	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
		wantSPA  bool
	}{
		{name: "system endpoint", method: http.MethodGet, path: "/api/system", wantCode: http.StatusOK},
		{name: "unknown api path", method: http.MethodGet, path: "/api/unknown", wantCode: http.StatusNotFound},
		{name: "root goes to spa", method: http.MethodGet, path: "/", wantCode: http.StatusOK, wantSPA: true},
		{name: "client route goes to spa", method: http.MethodGet, path: "/profiles", wantCode: http.StatusOK, wantSPA: true},
	}
	router := newRouter(spa)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if gotSPA := rec.Body.String() == "spa"; gotSPA != tt.wantSPA {
				t.Fatalf("served by spa = %v, want %v", gotSPA, tt.wantSPA)
			}
		})
	}
}

func TestListenAddress(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "default when unset", env: "", want: defaultListenAddress},
		{name: "environment override", env: "0.0.0.0:9000", want: "0.0.0.0:9000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TUNNELDECK_LISTEN", tt.env)
			if got := listenAddress(); got != tt.want {
				t.Fatalf("listenAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}
