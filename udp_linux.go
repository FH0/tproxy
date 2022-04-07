package tproxy

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// UDPListener normal and TPROXY listener
type UDPListener struct {
	listener     *net.UDPConn
	listenerAddr netip.AddrPort
	raw4         int
	raw6         int
}

// ReadFromUDPAddrPort like net package
func (u *UDPListener) ReadFromUDPAddrPort(buf []byte) (nread int, saddr, daddr netip.AddrPort, err error) {
	oob := make([]byte, 64)
	var oobn int
	var saddrUDPAddr *net.UDPAddr
	nread, oobn, _, saddrUDPAddr, err = u.listener.ReadMsgUDP(buf, oob)
	if err != nil {
		return
	}
	saddr = saddrUDPAddr.AddrPort()

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			ip, ok := netip.AddrFromSlice(msg.Data[4:8])
			if !ok {
				err = errors.New("ipv4 addr error")
				return
			}
			daddr = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(msg.Data[2:4]))
			return
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip, ok := netip.AddrFromSlice(msg.Data[8:24])
			if !ok {
				err = errors.New("ipv6 addr error")
				return
			}
			daddr = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(msg.Data[2:4]))
			return
		}
	}

	return
}

// WriteToUDPAddrPort like net package
func (u *UDPListener) WriteToUDPAddrPort(buf []byte, saddr, daddr netip.AddrPort) (err error) {
	if saddr == u.listenerAddr {
		_, err = u.listener.WriteToUDPAddrPort(buf, daddr)
		return
	}

	if saddr.Addr().Is4() {
		return u.writeToRawUDPIPv4(buf, saddr, daddr)
	}
	return u.writeToRawUDPIPv6(buf, saddr, daddr)
}

func (u *UDPListener) writeToRawUDPIPv4(buf []byte, saddr, daddr netip.AddrPort) (err error) {
	totalLen := header.IPv4MinimumSize + header.UDPMinimumSize + len(buf)
	ipHeader := header.IPv4(
		append(
			make([]byte, totalLen-len(buf)),
			buf...,
		),
	)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.Address(saddr.Addr().AsSlice()),
		DstAddr:     tcpip.Address(daddr.Addr().AsSlice()),
		Options:     []header.IPv4SerializableOption{},
	})
	ipHeader.SetChecksum(0)
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())

	udpHeader := header.UDP(ipHeader.Payload())
	udpHeader.Encode(&header.UDPFields{
		SrcPort: uint16(saddr.Port()),
		DstPort: uint16(daddr.Port()),
		Length:  uint16(header.UDPMinimumSize + len(buf)),
	})
	udpHeader.SetChecksum(0)
	udpHeader.SetChecksum(
		^udpHeader.CalculateChecksum(
			header.Checksum(
				udpHeader.Payload(),
				header.PseudoHeaderChecksum(
					header.UDPProtocolNumber,
					ipHeader.SourceAddress(),
					ipHeader.DestinationAddress(),
					udpHeader.Length(),
				),
			),
		),
	)

	err = syscall.Sendto(u.raw4, ipHeader, 0, &syscall.SockaddrInet4{})
	return
}

func (u *UDPListener) writeToRawUDPIPv6(buf []byte, saddr, daddr netip.AddrPort) (err error) {
	totalLen := header.IPv6MinimumSize + header.UDPMinimumSize + len(buf)
	ipHeader := header.IPv6(
		append(
			make([]byte, totalLen-len(buf)),
			buf...,
		),
	)
	ipHeader.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.IPv6MinimumSize + len(buf)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.Address(saddr.Addr().AsSlice()),
		DstAddr:           tcpip.Address(daddr.Addr().AsSlice()),
	})

	udpHeader := header.UDP(ipHeader.Payload())
	udpHeader.Encode(&header.UDPFields{
		SrcPort: uint16(saddr.Port()),
		DstPort: uint16(daddr.Port()),
		Length:  uint16(header.UDPMinimumSize + len(buf)),
	})
	udpHeader.SetChecksum(0)
	udpHeader.SetChecksum(
		^udpHeader.CalculateChecksum(
			header.Checksum(
				udpHeader.Payload(),
				header.PseudoHeaderChecksum(
					header.UDPProtocolNumber,
					ipHeader.SourceAddress(),
					ipHeader.DestinationAddress(),
					udpHeader.Length(),
				),
			),
		),
	)

	err = syscall.Sendto(u.raw6, ipHeader, 0, &syscall.SockaddrInet6{})
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
func ListenUDP(addr string) (udpListener *UDPListener, err error) {
	udpListener = &UDPListener{}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	udpListener.listener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	udpListener.listenerAddr = udpListener.listener.LocalAddr().(*net.UDPAddr).AddrPort()

	file, err := udpListener.listener.File()
	if err != nil {
		return
	}
	fd := int(file.Fd())
	if udpListener.listener.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Is4() ||
		udpListener.listener.LocalAddr().(*net.UDPAddr).AddrPort().Addr() == netip.MustParseAddr("::") {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IP, unix.IP_TRANSPARENT, 1)
		if err != nil {
			return
		}
		err = syscall.SetsockoptInt(fd, syscall.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		if err != nil {
			return
		}
	}
	if udpListener.listener.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Is6() {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		if err != nil {
			return
		}
		err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if err != nil {
			return
		}
	}

	err = file.Close()
	if err != nil {
		return
	}

	udpListener.raw4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK, syscall.IPPROTO_RAW)
	if err != nil {
		return
	}
	udpListener.raw6, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK, syscall.IPPROTO_RAW)
	if err != nil {
		return
	}

	return
}
