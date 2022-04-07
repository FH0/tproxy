package tproxy

import (
	"net"
)

// ListenTCP address is [::], dual stack
func ListenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
