package main

import (
	"fmt"
	"log"
	"net"

	"github.com/jordanabderrachid/dns/dns"
)

func main() {
	fmt.Println("dns client")
	m, err := dns.NewQuestion("google.com")
	panicOnErr(err)

	conn, err := net.Dial("udp", "8.8.8.8:53")
	panicOnErr(err)
	defer conn.Close()

	n, err := conn.Write(m.ToBytes())
	panicOnErr(err)
	log.Printf("wrote %d bytes", n)

	resp := make([]byte, 512)
	n, err = conn.Read(resp)
	panicOnErr(err)
	log.Printf("Read %d bytes (%v)", n, resp)
}

func panicOnErr(err error) {
	if err != nil {

		panic(err)
	}
}
