package proxy

import (
	"net/http"
	"os"

	"github.com/rakyll/statik/fs"

	// Statik makes assets available via a blank import
	_ "github.com/buzzfeed/sso/internal/auth/statik"
)

// noDirectoryFilesystem is used to prevent an http.FileServer from providing directory listings
type noDirectoryFS struct {
	fs http.FileSystem
}

func (fs noDirectoryFS) Open(name string) (http.File, error) {
	f, err := fs.fs.Open(name)

	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// prevent directory listings
	if stat.IsDir() {
		return nil, os.ErrNotExist
	}

	return f, nil
}

//go:generate $GOPATH/bin/statik -f -src=./static

func loadFSHandler() (http.Handler, error) {
	statikFS, err := fs.New()
	if err != nil {
		return nil, err
	}

	return http.FileServer(noDirectoryFS{statikFS}), nil
}
