package trans

import "net"

type Conn struct {
	Conn    net.Conn
	UdpAddr *net.UDPAddr
}
