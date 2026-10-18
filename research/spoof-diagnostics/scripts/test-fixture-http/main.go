// This is a local-only development/CI fixture, never included in release.
// It replaces the archived Python HTTP-server test dependency with Go stdlib.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	root := flag.String("dir", "", "directory with disposable offline archives")
	portFile := flag.String("port-file", "", "file where ephemeral loopback port is written")
	flag.Parse()
	if *root == "" || *portFile == "" {
		fmt.Fprintln(os.Stderr, "requires --dir and --port-file")
		os.Exit(2)
	}
	stat, err := os.Stat(*root)
	if err != nil || !stat.IsDir() {
		fmt.Fprintln(os.Stderr, "fixture archive directory invalid")
		os.Exit(2)
	}
	if _, err := os.Lstat(*portFile); !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "port file must not exist")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	f, err := os.OpenFile(*portFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, err = fmt.Fprintln(f, port)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Remove(*portFile)
		os.Exit(1)
	}
	server := &http.Server{
		Handler:           http.FileServer(http.Dir(filepath.Clean(*root))),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
