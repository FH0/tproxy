package tproxy

import (
	"net"
	"strconv"
)

// ListenTCP address is [::], dual stack
func ListenTCP(port uint16) (net.Listener, error) {
	return net.Listen("tcp", "[::]:"+strconv.Itoa(int(port)))
}
