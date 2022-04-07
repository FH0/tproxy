package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/FH0/tproxy"
)

var (
	tListener net.Listener
	uListener *tproxy.UDPListener
)

func init() {
	var err error
	tListener, err = tproxy.ListenTCP(54321)
	if err != nil {
		panic(err)
	}
	uListener, err = tproxy.ListenUDP(54321)
	if err != nil {
		panic(err)
	}
}

func testTCPNormal() {
	go func() {
		_, err := net.Dial("tcp", tListener.Addr().String())
		if err != nil {
			panic(err)
		}
	}()

	conn, err := tListener.Accept()
	if err != nil {
		panic(err)
	}
	if conn.LocalAddr().(*net.TCPAddr).Port != tListener.Addr().(*net.TCPAddr).Port {
		panic(fmt.Sprintf("%v %v\n", conn.LocalAddr(), tListener.Addr()))
	}
}

func testUDPNormal() {
	go func() {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54322})
		if err != nil {
			panic(err)
		}
		_, err = conn.WriteToUDPAddrPort([]byte("abcd"), netip.MustParseAddrPort("127.0.0.1:54321"))
		if err != nil {
			panic(err)
		}
	}()

	buf := make([]byte, 100)
	nread, saddr, daddr, err := uListener.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	if saddr.Port() != 54322 ||
		daddr.Port() != uint16(uListener.LocalAddr().(*net.UDPAddr).Port) ||
		string(buf[:nread]) != "abcd" {
		panic(fmt.Sprintf("%v %v %v\n", saddr.Port(), daddr.Port(), string(buf[:nread])))
	}
}

func main() {
	testTCPNormal()
	testUDPNormal()
}
