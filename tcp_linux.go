package tproxy

import (
	"encoding/binary"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

//revive:disable
// SO_ORIGINAL_DST syscall and unix not contain
const SO_ORIGINAL_DST = 80

//revive:enable

type tcpConn struct {
	net.Conn
	daddr net.Addr
}

// LocalAddr returns the local network address, if known.
func (t *tcpConn) LocalAddr() net.Addr {
	return t.daddr
}

type tcpListener struct {
	net.Listener
}

// Accept like net package
func (t *tcpListener) Accept() (net.Conn, error) {
	conn, err := t.Listener.Accept()
	if err != nil {
		return nil, err
	}

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		return nil, err
	}
	fd := file.Fd()

	var daddr net.Addr
	mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		mtuInfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)
		if err != nil {
			daddr = conn.LocalAddr()
		} else {
			daddr = &net.TCPAddr{
				IP:   mtuInfo.Addr.Addr[:],
				Port: int(binary.BigEndian.Uint16([]byte{byte(mtuInfo.Addr.Port), byte(mtuInfo.Addr.Port >> 8)})),
			}
		}
	} else {
		daddr = &net.TCPAddr{
			IP:   mreq.Multiaddr[4:8],
			Port: int(binary.BigEndian.Uint16(mreq.Multiaddr[2:])),
		}
	}

	return &tcpConn{
		Conn:  conn,
		daddr: daddr,
	}, nil
}

// ListenTCP address is [::], dual stack
func ListenTCP(port uint16) (_ net.Listener, err error) {
	listener := &tcpListener{}

	listener.Listener, err = net.Listen("tcp", "[::]:"+strconv.Itoa(int(port)))
	if err != nil {
		return
	}

	file, err := listener.Listener.(*net.TCPListener).File()
	if err != nil {
		return
	}
	fd := int(file.Fd())
	err = syscall.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err != nil {
		return
	}
	err = syscall.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	if err != nil {
		return
	}
	err = file.Close()
	if err != nil {
		return
	}

	return listener, err
}
