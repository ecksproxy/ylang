package remote

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imlgw/ylang/internal/codec"
	"github.com/imlgw/ylang/internal/trans"
	"log"
	"net"
)

type TCPListener struct {
	listener net.Listener
	addr     string
	closed   bool
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

func processTCP() {
	queue := tcpQueue
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	for {
		// tcp包payload是ip包数据，最大65535
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipLayer == nil {
			log.Fatal("Could not decode IPv4 codec")
		}

		// 以太网层
		newEthLayer := &layers.Ethernet{
			SrcMAC:       localNic.HwAddr(),
			DstMAC:       gatewayNic.HwAddr(),
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 修正 SrcIP
		ipLayer.SrcIP = localNic.IPAddr()
		// 记录DstIP映射关系
		sktInfo := trans.Socket{IP: ipLayer.SrcIP.String()}

		newTransLayer := packet.TransportLayer()

		tcpLayer := newTransLayer.(*layers.TCP)
		sktInfo.Port = uint16(tcpLayer.SrcPort)
		sktInfo.Protocol = uint8(layers.IPProtocolTCP)
		// 设置伪头部
		if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
			fmt.Println(err)
			return
		}

		// TODO: LOCK优化
		lock.Lock()
		nat[sktInfo] = conn
		lock.Unlock()

		serializeLayers, err := codec.SerializeLayers(newEthLayer, ipLayer, newTransLayer.(gopacket.SerializableLayer),
			gopacket.Payload(newTransLayer.LayerPayload()))
		if err != nil {
			fmt.Println(err)
			return
		}
		// 转发给目标服务器
		if err := localNic.Handle().WritePacketData(serializeLayers); err != nil {
			fmt.Println(err)
		}
	}
}
