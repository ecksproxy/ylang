package remote

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imlgw/ylang/internal/codec"
	"github.com/imlgw/ylang/internal/trans"
	"log"
	"net"
	"time"
)

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

type UDPPacket struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
}

func NewUDPListener(addr string, in chan<- *UDPPacket) (*UDPListener, error) {
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
			in <- &UDPPacket{
				pc:      l,
				rAddr:   remoteAddr,
				payload: buf[:n],
			}
		}
	}()

	return sl, nil
}

func processUDP() {
	queue := udpQueue
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(conn *UDPPacket) {
	packet := gopacket.NewPacket(conn.payload, layers.LayerTypeIPv4, gopacket.NoCopy)
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
	skt := trans.Socket{IP: ipLayer.SrcIP.String()}

	newTransLayer := packet.TransportLayer()
	// 构建传输层数据
	udpLayer := newTransLayer.(*layers.UDP)
	skt.Port = uint16(udpLayer.SrcPort)
	skt.Protocol = uint8(layers.IPProtocolUDP)

	// 设置伪头部
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		fmt.Println(err)
		return
	}

	// TODO: LOCK优化
	lock.Lock()
	nat[skt] = conn
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

func (p *UDPPacket) Read(b []byte) (n int, err error) {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) Write(b []byte) (n int, err error) {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) Close() error {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) LocalAddr() net.Addr {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) RemoteAddr() net.Addr {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) SetDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) SetReadDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (p *UDPPacket) SetWriteDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}
