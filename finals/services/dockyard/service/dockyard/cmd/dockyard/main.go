package main

import (
	"log"
	"net/http"
	"os"

	"dockyard/internal/api"
	"dockyard/internal/auth"
	dbpkg "dockyard/internal/db"
)

func main() {
	dbPath := getenv("DB_PATH", "/data/dockyard.db")
	blobRoot := getenv("BLOB_ROOT", "/data")
	keyPath := getenv("KEY_PATH", "/data/token.key")
	addr := getenv("LISTEN", ":7005")

	if err := os.MkdirAll(blobRoot, 0755); err != nil {
		log.Fatalf("mkdir blob root: %v", err)
	}
	if err := auth.LoadOrGenKey(keyPath); err != nil {
		log.Fatalf("load key: %v", err)
	}

	database, err := dbpkg.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}

	srv := &api.Server{DB: database, BlobRoot: blobRoot}
	log.Printf("dockyard listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
