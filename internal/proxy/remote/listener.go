package remote

import "C"
import "net"

type TCPListener struct {
	listener net.Listener
	addr     string
	closed   bool
}

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
}

func NewTCPListener(addr string, in chan<- net.Conn) (*TCPListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &TCPListener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			in <- c
		}
	}()

	return sl, nil
}

func NewUDPListener(addr string, in chan<- *packet) (*UDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	// TODO: UDPReuse
	// if err := sockopt.UDPReuseaddr(l.(*net.UDPConn)); err != nil {
	// 	log.Warnln("Failed to Reuse UDP Address: %s", err)
	// }

	sl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}
	go func() {
		for {
			// TODO: alloc优化，sync.Pool
			buf := make([]byte, 65535)
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			in <- &packet{
				pc:      l,
				rAddr:   remoteAddr,
				payload: buf[:n],
			}
		}
	}()

	return sl, nil
}
