package server

import (
	"crypto/tls"
	"log"
)

func Run(address string, certificate tls.Certificate) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %e\n", err)
	}
	for {
		_conn, err := listener.Accept()
		if err != nil {
			log.Printf("Couldn't accept connection from client: %e\n", err)
			continue
		}
		conn := _conn.(*tls.Conn)
		go startConnectionHandler(conn)
	}
}