package tproxy

import (
	"net"
	"net/netip"
)

// UDPListener normal and TPROXY listener
type UDPListener struct {
	listener     *net.UDPConn
	listenerAddr netip.AddrPort
}

// ReadFromUDPAddrPort like net package
func (u *UDPListener) ReadFromUDPAddrPort(buf []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	nread, saddr, err := u.listener.ReadFromUDPAddrPort(buf)
	return nread, saddr, u.listenerAddr, err
}

// WriteToUDPAddrPort like net package
func (u *UDPListener) WriteToUDPAddrPort(buf []byte, saddr, daddr netip.AddrPort) (err error) {
	_, err = u.listener.WriteToUDPAddrPort(buf, daddr)
	return
}

// Close like net package
func (u *UDPListener) Close() (err error) {
	return u.listener.Close()
}

// LocalAddr returns the local network address, if known.
func (u *UDPListener) LocalAddr() net.Addr {
	return u.listener.LocalAddr()
}

// ListenUDP like net package
func ListenUDP(port uint16) (udpListener *UDPListener, err error) {
	udpListener = &UDPListener{}
	udpListener.listener, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: int(port)})
	if err != nil {
		return
	}
	udpListener.listenerAddr = udpListener.listener.LocalAddr().(*net.UDPAddr).AddrPort()
	return
}
