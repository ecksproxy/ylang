package lan

import (
	"github.com/google/gopacket"
	"math/rand"
	"net"
	"time"
)

type ActiveHostConn struct {
	Mac  net.HardwareAddr
	Port uint16
	IP   net.IP
}

type SocketInfo struct {
	IP       string
	Port     uint16
	Protocol uint8
}

// FindSrcPort 客户端源端口选择，模拟系统栈过程
func FindSrcPort(packet gopacket.Packet) (uint16, error) {
	rand.Seed(time.Now().UnixNano())
	return uint16(rand.Intn(65535-1024) + 1024), nil
}
