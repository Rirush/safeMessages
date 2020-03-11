package main

import (
	"crypto/tls"
	"github.com/Rirush/safeMessages/smserver/database"
	"github.com/Rirush/safeMessages/smserver/handler"
	"github.com/Rirush/safeMessages/smserver/server"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	// TODO: Load configuration
	// TODO: Setup logging and migrate database
	// TODO: Load certificates from custom location
	err := handler.ConnectToNats(nats.DefaultURL)
	if err != nil {
		log.Fatalf("Cannot connect to NATS: %e\n", err)
	}
	db, err := sqlx.Open("postgres", "postgres://chat:securechat@localhost:5432/chat?sslmode=disable")
	if err != nil {
		log.Fatalf("Cannot connect to database: %e\n", err)
	}
	database.Store(db)
	err = database.PrepareStatements()
	if err != nil {
		log.Fatalf("Cannot connect to database: %e\n", err)
	}
	certificate, err := tls.LoadX509KeyPair("cert.crt", "cert.key")
	if err != nil {
		log.Fatalf("Cannot load certificate: %e\n", err)
	}
	server.Run(":1337", certificate)
}
