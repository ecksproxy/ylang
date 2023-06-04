package wan

import "net"

type cliConn struct {
	conn    net.Conn
	udpAddr *net.UDPAddr
}
