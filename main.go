package main

import (
	"log"
	"net"
	"time"
)

func main() {
	go startListen()
	time.Sleep(5 * time.Second)
	if err := runClient("127.0.0.1:8443", "localhost"); err != nil {
		log.Fatalf("failed to run client: %v", err)
	}
}

func startListen() {
	certDER, certPriv, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("failed to generate self-signed certificate: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil {
		log.Fatalf("faield to listen: %v", err)
	}
	log.Println("server side is starting, listen on 127.0.0.1:8443")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept new conection: %v", err)
			continue
		}
		go serveTLS(conn, certDER, certPriv)
	}
}
