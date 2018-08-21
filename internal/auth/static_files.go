package auth

import (
	"net/http"
	"os"
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
