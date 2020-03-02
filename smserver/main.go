package main

import (
	"crypto/tls"
	"github.com/Rirush/safeMessages/smserver/server"
	"log"
)

func main() {
	// TODO: Load configuration
	// TODO: Setup logging and migrate database
	// TODO: Load certificates from custom location
	certificate, err := tls.LoadX509KeyPair("cert.crt", "cert.key")
	if err != nil {
		log.Fatalf("Cannot load certificate: %e\n", err)
	}
	server.Run(":1337", certificate)
}
