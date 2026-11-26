package web

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// dist holds the Vite build output. The directory always contains a committed
// .gitkeep so the package compiles before the frontend has been built.
//
//go:embed all:dist
var dist embed.FS

const indexFile = "index.html"

// iconTypes lists the app-icon and manifest types Go's built-in MIME table
// lacks; registering them keeps the result independent of the host's tables.
var iconTypes = map[string]string{
	".ico":         "image/x-icon",
	".webmanifest": "application/manifest+json",
}

func init() {
	for ext, typ := range iconTypes {
		if err := mime.AddExtensionType(ext, typ); err != nil {
			panic(fmt.Errorf("register MIME type for %s: %w", ext, err))
		}
	}
}

// Handler serves the embedded single-page application.
func Handler() http.Handler {
	assets, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return NewHandler(assets)
}

// NewHandler serves the files in assets and answers every request for a
// missing file with index.html, so client-side routes work on reload.
func NewHandler(assets fs.FS) http.Handler {
	files := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isServableFile(assets, r.URL.Path) {
			files.ServeHTTP(w, r)
			return
		}
		serveIndex(w, assets)
	})
}

func isServableFile(assets fs.FS, urlPath string) bool {
	name := strings.TrimPrefix(path.Clean(urlPath), "/")
	if name == "" || name == "." || name == indexFile {
		return false
	}
	info, err := fs.Stat(assets, name)
	return err == nil && !info.IsDir()
}

func serveIndex(w http.ResponseWriter, assets fs.FS) {
	index, err := fs.ReadFile(assets, indexFile)
	if errors.Is(err, fs.ErrNotExist) {
		http.Error(w, "web UI not built: run npm --prefix web run build", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "read index.html", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}
