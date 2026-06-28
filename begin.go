package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal("Ошибка загрузки сертификата", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", "0.0.0.0:1081", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 + TLS прокси запущен на :1081")

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
	fmt.Printf("[%s] тип адреса: 0x%02x команда: 0x%02x версия: 0x%02x\n",
		client.RemoteAddr(), req[3], req[1], req[0])

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

	case 0x04:
		addr := make([]byte, 16)
		io.ReadFull(client, addr)
		port := make([]byte, 2)
		io.ReadFull(client, port)
		targetAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			binary.BigEndian.Uint16(addr[0:2]),
			binary.BigEndian.Uint16(addr[2:4]),
			binary.BigEndian.Uint16(addr[4:6]),
			binary.BigEndian.Uint16(addr[6:8]),
			binary.BigEndian.Uint16(addr[8:10]),
			binary.BigEndian.Uint16(addr[10:12]),
			binary.BigEndian.Uint16(addr[12:14]),
			binary.BigEndian.Uint16(addr[14:16]),
			binary.BigEndian.Uint16(port))
	}

	fmt.Printf("[%s] -> %s\n", client.RemoteAddr(), targetAddr)

	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Printf("[%s] Ошибка подключения к %s: %v\n", client.RemoteAddr(), targetAddr, err)
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	fmt.Printf("[%s] ТУННЕЛЬ ОТКРЫТ -> %s\n", client.RemoteAddr(), targetAddr)
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done

	fmt.Printf("[%s] ТУННЕЛЬ ЗАКРЫТ <- %s\n", client.RemoteAddr(), targetAddr)

}
