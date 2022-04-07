package main

import (
	"fmt"
	"net"
	"testing"
)

func TestTCPNormal(t *testing.T) {
	testTCPNormal()
}

/*
ip rule add fwmark 54321 table 54321
ip route replace local default dev lo table 54321
iptables -t mangle -I OUTPUT -p tcp -d 1.2.3.4 -j MARK --set-mark 54321
iptables -t mangle -I PREROUTING -p tcp -m mark --mark 54321 -j TPROXY --on-ip 127.0.0.1 --on-port 54321 --tproxy-mark 54321
*/
func TestTCPTproxy(t *testing.T) {
	go func() {
		_, err := net.Dial("tcp", "1.2.3.4:80")
		if err != nil {
			panic(err)
		}
	}()

	conn, err := tListener.Accept()
	if err != nil {
		panic(err)
	}
	if conn.LocalAddr().String() != "1.2.3.4:80" {
		panic(fmt.Sprintf("%v\n", conn.LocalAddr()))
	}
}

/*
iptables -t nat -I OUTPUT -p tcp -d 1.2.3.4 -j REDIRECT --to 54321
*/
func TestTCPRedirect(t *testing.T) {
	go func() {
		_, err := net.Dial("tcp", "1.2.3.4:80")
		if err != nil {
			panic(err)
		}
	}()

	conn, err := tListener.Accept()
	if err != nil {
		panic(err)
	}
	if conn.LocalAddr().String() != "1.2.3.4:80" {
		panic(fmt.Sprintf("%v\n", conn.LocalAddr()))
	}
}

func TestUDPNormal(t *testing.T) {
	testUDPNormal()
}

/*
ip rule add fwmark 54321 table 54321
ip route replace local default dev lo table 54321
iptables -t mangle -I OUTPUT -p udp -d 1.2.3.4 -j MARK --set-mark 54321
iptables -t mangle -I PREROUTING -p udp -m mark --mark 54321 -j TPROXY --on-ip 127.0.0.1 --on-port 54321 --tproxy-mark 54321
*/
func TestUDPTproxy(t *testing.T) {
	go func() {
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53})
		if err != nil {
			panic(err)
		}
		_, err = conn.Write([]byte("abcd"))
		if err != nil {
			panic(err)
		}
	}()

	buf := make([]byte, 100)
	nread, _, daddr, err := uListener.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	if daddr.String() != "1.2.3.4:53" || string(buf[:nread]) != "abcd" {
		panic(fmt.Sprintf("%v %v\n", daddr, string(buf[:nread])))
	}
}
