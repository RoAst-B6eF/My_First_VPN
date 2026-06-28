package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:1081")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 прокси запущен на :1081")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Ошибка:", err)
			continue
		}
		go handleClient(conn)
	}

}

func handleClient(client net.Conn) {
	defer client.Close()

	fmt.Println("Клиент подключился: ", client.RemoteAddr())

	header := make([]byte, 2)
	io.ReadFull(client, header)

	methods := make([]byte, header[1])
	io.ReadFull(client, methods)

	client.Write([]byte{0x05, 0x00})

	req := make([]byte, 4)
	io.ReadFull(client, req)

	var targetAddr string
	switch req[3] {
	case 0x01:
		addr := make([]byte, 4)
		io.ReadFull(client, addr)
		port := make([]byte, 2)
		io.ReadFull(client, port)
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			addr[0], addr[1], addr[2], addr[3],
			binary.BigEndian.Uint16(port))

	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(client, lenBuf)
		domain := make([]byte, lenBuf[0])
		io.ReadFull(client, domain)
		port := make([]byte, 2)
		io.ReadFull(client, port)
		targetAddr = fmt.Sprintf("%s:%d",
			domain, binary.BigEndian.Uint16(port))
	}

	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}
