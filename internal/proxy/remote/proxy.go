package remote

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/imlgw/ylang/internal/codec"
	"github.com/imlgw/ylang/internal/config"
	"github.com/imlgw/ylang/internal/eth"
	"github.com/imlgw/ylang/internal/trans"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"sync"
)

var (
	tcpQueue   = make(chan net.Conn, 200)
	tcpListen  *TCPListener
	udpQueue   = make(chan *packet, 200)
	udpListen  *UDPListener
	listenPort int
	nicName    string
	nat        map[trans.Socket]*cliConn
	lock       sync.Mutex
	localNic   *eth.Device
	gatewayNic *eth.Device
	// 网关ip
	gatewayIp, _ = gateway.DiscoverGateway()
)

type Proxy struct {
	conn       net.Conn
	localNic   *eth.Device
	gatewayNic *eth.Device
	nicHandle  *pcap.Handle
}

func TCPIn() chan<- net.Conn {
	return tcpQueue
}

func UDPIn() chan<- *packet {
	return udpQueue
}

func NewRemoteProxy(cfg *config.Server) {
	listenPort = cfg.ListenPort
	nicName = cfg.NicName
	nat = make(map[trans.Socket]*cliConn)

	// 获取指定nic设备
	localNic = eth.FindNIC(nicName)

	handle, err := pcap.OpenLive(localNic.Name(), 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}

	addr := fmt.Sprintf("%s:%d", "127.0.0.1", listenPort)
	tcpListen, err = NewTCPListener(addr, TCPIn())
	udpListen, err = NewUDPListener(addr, UDPIn())
	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayNic, _ = eth.FindGatewayNIC(localNic, handle, gatewayIp)
}

func (wanTun *Proxy) ForwardClientData() {
	var err error
	for {
		// tcp包payload是ip包数据，最大65535
		buf := make([]byte, 65535)
		n := 0
		var client *net.UDPAddr
		switch wanTun.conn.(type) {
		case *net.UDPConn:
			conn := wanTun.conn.(*net.UDPConn)
			n, client, _ = conn.ReadFromUDP(buf)
		case *net.TCPConn:
			n, err = wanTun.conn.Read(buf)
			if err != nil {
				fmt.Println("read from client error", err)
				return
			}
		default:
			fmt.Println("unsupported mode")
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipLayer == nil {
			log.Fatal("Could not decode IPv4 codec")
		}

		// 以太网层
		newEthLayer := &layers.Ethernet{
			SrcMAC:       wanTun.localNic.HwAddr(),
			DstMAC:       wanTun.gatewayNic.HwAddr(),
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 修正 SrcIP
		ipLayer.SrcIP = wanTun.localNic.IPAddr()
		// 记录DstIP映射关系
		sktInfo := trans.Socket{IP: ipLayer.SrcIP.String()}

		newTransLayer := packet.TransportLayer()
		// 构建传输层数据
		switch newTransLayer.LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := newTransLayer.(*layers.TCP)
			sktInfo.Port = uint16(tcpLayer.SrcPort)
			sktInfo.Protocol = uint8(layers.IPProtocolTCP)
			// 设置伪头部
			if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}
		case layers.LayerTypeUDP:
			udpLayer := newTransLayer.(*layers.UDP)
			sktInfo.Port = uint16(udpLayer.SrcPort)
			sktInfo.Protocol = uint8(layers.IPProtocolUDP)
			// 设置伪头部
			if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}
		default:
			fmt.Printf("unsupport lan codec %s", packet.TransportLayer().LayerType())
			return
		}

		// TODO: LOCK优化
		lock.Lock()
		nat[sktInfo] = &cliConn{conn: wanTun.conn, udpAddr: client}
		lock.Unlock()

		serializeLayers, err := codec.SerializeLayers(newEthLayer, ipLayer, newTransLayer.(gopacket.SerializableLayer),
			gopacket.Payload(newTransLayer.LayerPayload()))
		if err != nil {
			fmt.Println(err)
			return
		}
		// 转发给目标服务器
		if err := wanTun.nicHandle.WritePacketData(serializeLayers); err != nil {
			fmt.Println(err)
		}
	}
}

func (wanTun *Proxy) BackwardServerData() {
	// 监听所有进入的tcp/udp的包，除了client发来的包
	err := wanTun.nicHandle.SetBPFFilter(fmt.Sprintf("ip && ((tcp || udp) && (not dst port %d)) && (dst host %s)", listenPort, wanTun.localNic.IPAddr().String()))
	if err != nil {
		fmt.Println(err)
	}
	receivePacketCh := gopacket.NewPacketSource(wanTun.nicHandle, wanTun.nicHandle.LinkType()).Packets()
	for {
		packet := <-receivePacketCh
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		sktInfo := trans.Socket{IP: ipLayer.DstIP.String()}
		switch packet.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := packet.TransportLayer().(*layers.TCP)
			sktInfo.Port = uint16(tcpLayer.DstPort)
			sktInfo.Protocol = uint8(layers.IPProtocolTCP)
		case layers.LayerTypeUDP:
			udpLayer := packet.TransportLayer().(*layers.UDP)
			sktInfo.Port = uint16(udpLayer.DstPort)
			sktInfo.Protocol = uint8(layers.IPProtocolUDP)
		default:
			fmt.Println("unsupported codec")
		}

		// nat记录客户端连接
		lock.Lock()
		cli, ok := nat[sktInfo]
		lock.Unlock()
		if !ok {
			continue
		}

		// fmt.Printf("recevie data: %s \n", packet.String())

		// IP包数据序列化后通过tcp回传给client
		options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(ipLayer.Payload)); err != nil {
			fmt.Println(err)
		}

		switch cli.conn.(type) {
		case *net.UDPConn:
			udpConn := cli.conn.(*net.UDPConn)
			if _, err := udpConn.WriteToUDP(packet.LinkLayer().LayerPayload(), cli.udpAddr); err != nil {
				fmt.Println(err)
				return
			}
		case *net.TCPConn:
			if _, err := cli.conn.Write(packet.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
