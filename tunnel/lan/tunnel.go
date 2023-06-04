package lan

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/imlgw/ylang/codec"
	"github.com/imlgw/ylang/config"
	"github.com/imlgw/ylang/internal/eth"
	"github.com/imlgw/ylang/internal/trans"
	"log"
	"net"
)

var (
	targetIP        string
	targetGatewayIP string
	serverIP        string
	serverPort      int
	mode            string
	nicName         string
	tunnelQueue     = make(chan *Tunnel, 10)
	nat             map[trans.Socket]*Host
)

type Tunnel struct {
	conn      net.Conn
	nic       *eth.Device
	nicHandle *pcap.Handle
}

type Host struct {
	Mac  net.HardwareAddr
	Port uint16
	IP   net.IP
}

func Nat() map[trans.Socket]*Host {
	return nat
}

func (lanTun *Tunnel) Conn() net.Conn {
	return lanTun.conn
}

func (lanTun *Tunnel) Nic() *eth.Device {
	return lanTun.nic
}

func (lanTun *Tunnel) NicHandle() *pcap.Handle {
	return lanTun.nicHandle
}

func GetTargetIP() string {
	return targetIP
}

func GetTargetGatewayIP() string {
	return targetGatewayIP
}

func GetServerIP() string {
	return serverIP
}

func GetServerPort() int {
	return serverPort
}

func GetNicName() string {
	return nicName
}

func GetMode() string {
	return mode
}

func Tunnels() chan *Tunnel {
	return tunnelQueue
}

func NewTunnel(cfg *config.Client) (*Tunnel, error) {
	var newTun = &Tunnel{}
	var conn net.Conn
	var err error
	switch cfg.Mode {
	case "udp":
		conn, err = net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.ParseIP(cfg.ServerIP),
			Port: cfg.ServerPort,
		})
		if err != nil {
			fmt.Println(err)
		}
	case "tcp":
		conn, err = net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   net.ParseIP(cfg.ServerIP),
			Port: cfg.ServerPort,
		})
		if err != nil {
			fmt.Println(err)
		}
	case "kcp":
	default:
		fmt.Println("unsupported mode")
	}
	mode = cfg.Mode
	serverIP = cfg.ServerIP
	serverPort = cfg.ServerPort
	targetIP = cfg.TargetIP
	targetGatewayIP = cfg.TargetGatewayIP
	nat = make(map[trans.Socket]*Host)

	newTun.conn = conn
	nic := eth.FindNIC(cfg.NicName)
	handle, err := pcap.OpenLive(nic.Name(), 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	newTun.nicHandle = handle
	newTun.nic = nic
	return newTun, nil
}

// ForwardLanDevice 处理局域网设备包, 转发到server
func (lanTun *Tunnel) ForwardLanDevice() {
	// 局域网其他主机（ns）发出的tcp/udp包，以及arp请求的包
	if err := lanTun.NicHandle().SetBPFFilter(fmt.Sprintf("(ip && ((tcp || udp) && (src host %s))) || (arp[6:2] = 1 && dst host %s)",
		targetIP, targetGatewayIP)); err != nil {
		fmt.Println(err)
		return
	}
	packetSource := gopacket.NewPacketSource(lanTun.NicHandle(), lanTun.NicHandle().LinkType())
	for {
		// 监听局域网内设备
		packet := <-packetSource.Packets()
		if packet == nil {
			continue
		}
		// data, ci, err2 := handle.ReadPacketData()
		fmt.Println("from lan ns:", packet)
		ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		layer := packet.Layer(layers.LayerTypeARP)
		if layer != nil {
			// 如果是 ARPRequest 伪装层网关进行回应
			err := lanTun.handleARPSpoofing(layer.(*layers.ARP))
			if err != nil {
				fmt.Println(err)
			}
			continue
		}

		ac := &Host{Mac: ethernet.SrcMAC, IP: net.ParseIP(targetIP)}
		ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		sktInfo := trans.Socket{IP: ipv4.DstIP.String()}

		switch ipv4.Protocol {
		case layers.IPProtocolTCP:
			ac.Port = uint16(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).SrcPort)
			sktInfo.Protocol = uint8(layers.IPProtocolTCP)
			sktInfo.Port = uint16(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).DstPort)
		case layers.IPProtocolUDP:
			ac.Port = uint16(packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort)
			sktInfo.Protocol = uint8(layers.IPProtocolUDP)
			sktInfo.Port = uint16(packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort)
		default:
			fmt.Printf("unsupported protocol: %s\n", ipv4.Protocol)
		}
		// full-cone NAT 记录destIP -> MAC地址映射
		nat[sktInfo] = ac

		// 通过tcp/udp转发网络层数据
		if _, err := lanTun.Conn().Write(packet.LinkLayer().LayerPayload()); err != nil {
			fmt.Println(err)
			return
		}
	}
}

// BackwardLanDevice 处理回传的包，回传到局域网设备
func (lanTun *Tunnel) BackwardLanDevice() {
	for {
		// 接受server响应（也是网络层数据，最大65535）
		b := make([]byte, 1<<16-1)
		n, err := lanTun.Conn().Read(b)
		if err != nil {
			fmt.Println("receive from server error:", err)
			return
		}
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.NoCopy)

		fmt.Println("receive from server:", packet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipLayer == nil {
			log.Fatal("Could not decode IPv4 codec")
		}

		sktInfo := trans.Socket{IP: ipLayer.SrcIP.String()}
		switch ipLayer.Protocol {
		case layers.IPProtocolTCP:
			sktInfo.Protocol = uint8(layers.IPProtocolTCP)
			sktInfo.Port = uint16(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).SrcPort)
		case layers.IPProtocolUDP:
			sktInfo.Protocol = uint8(layers.IPProtocolUDP)
			sktInfo.Port = uint16(packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort)
		default:
			fmt.Printf("unsupported protocol: %s\n", ipLayer.Protocol)
		}

		ac, ok := nat[sktInfo]
		if !ok {
			continue
		}
		// 以太网层
		ethLayer := &layers.Ethernet{
			SrcMAC:       lanTun.Nic().HwAddr(),
			DstMAC:       ac.Mac,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 修正 SrcIP/DstIP
		ipLayer.DstIP = net.ParseIP(targetIP)

		// 修正传输层数据 SrcPort/DstPort
		newTransLayer := packet.TransportLayer()
		switch newTransLayer.LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := newTransLayer.(*layers.TCP)
			tcpLayer.DstPort = layers.TCPPort(ac.Port)
			// 设置伪头部
			if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}
		case layers.LayerTypeUDP:
			udpLayer := newTransLayer.(*layers.UDP)
			udpLayer.DstPort = layers.UDPPort(ac.Port)
			// 设置伪头部
			if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}

		default:
			fmt.Printf("unsupport lan codec %s", packet.TransportLayer().LayerType())
			return
		}

		// 回传给目标主机
		serializeLayers, err := codec.SerializeLayers(ethLayer, ipLayer, newTransLayer.(gopacket.SerializableLayer),
			gopacket.Payload(newTransLayer.LayerPayload()))
		if err != nil {
			fmt.Println(err)
			continue
		}
		if err := lanTun.NicHandle().WritePacketData(serializeLayers); err != nil {
			fmt.Println(err)
		}
	}
}

// handleARPSpoofing 处理ARP欺骗，伪装网关响应ARP请求
func (lanTun *Tunnel) handleARPSpoofing(arpReq *layers.ARP) error {
	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       lanTun.nic.HwAddr(),
		DstMAC:       arpReq.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}

	// ARP层
	arpLayer := &layers.ARP{
		AddrType:        arpReq.AddrType,
		Protocol:        arpReq.Protocol,
		HwAddressSize:   arpReq.HwAddressSize,
		ProtAddressSize: arpReq.ProtAddressSize,
		Operation:       layers.ARPReply,
		// 伪装成目标主机网关
		SourceHwAddress:   lanTun.nic.HwAddr(),
		SourceProtAddress: arpReq.DstProtAddress,
		DstHwAddress:      arpReq.SourceHwAddress,
		DstProtAddress:    arpReq.SourceProtAddress,
	}

	// 组装数据
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, ethLayer, arpLayer)
	if err != nil {
		return err
	}

	// write data
	if err := lanTun.nicHandle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}
	return nil
}
