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

	_, err = conn.Write(m.ToBytes())
	panicOnErr(err)

	resp := make([]byte, 512)
	_, err = conn.Read(resp)
	panicOnErr(err)

	receivedMessage, _, err := dns.MessageFromBytes(resp)
	panicOnErr(err)
	log.Printf("%s", receivedMessage.String())
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
