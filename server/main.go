package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/imlgw/ylang/internal/eth"
	"github.com/imlgw/ylang/internal/lan"
	"github.com/imlgw/ylang/internal/trans"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"sync"
)

var lock sync.Mutex

func main() {
	// 本地网卡名称
	nicName := ""
	// 本地网卡设备
	var nic *eth.Device
	// 本地网卡和下游client端的连接
	var cliConn net.Conn
	var mode = "udp"
	var listenPort = 54321
	var nat = make(map[lan.SocketInfo]*trans.Conn)
	// 获取指定nic设备
	nic = eth.FindNIC(nicName)

	// 网关ip
	gatewayIp, _ := gateway.DiscoverGateway()
	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayNIC, _ := eth.FindGatewayNIC(nic, gatewayIp)

	// 监听nic设备，通过NIC设备发送到目标服务器
	nicHandle, err := pcap.OpenLive(nic.Name(), 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer nicHandle.Close()
	// 监听所有进入的tcp/udp的包，除了client发来的包
	err = nicHandle.SetBPFFilter(fmt.Sprintf("ip && ((tcp || udp) && (not dst port %d)) && (dst host %s)", listenPort, nic.IPAddr().String()))
	if err != nil {
		fmt.Println(err)
	}

	// 监听客户端请求，转发给目标服务
	go func() {
		switch mode {
		case "udp":
			cliConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
			if err != nil {
				fmt.Println("udp err:", err)
			}
		case "tcp":
			listen, err := net.ListenTCP("tcp", &net.TCPAddr{
				IP:   nic.IPAddr(),
				Port: listenPort,
			})
			if err != nil {
				fmt.Println(err)
			}
			// TODO: 多客户端
			cliConn, err = listen.AcceptTCP()
			fmt.Printf("connect from: %s \n", cliConn.RemoteAddr().String())
		default:
			fmt.Println("unsupported mode")
		}

		for {
			// tcp包payload是ip包数据，最大65535
			buf := make([]byte, 65535)
			n := 0
			var client *net.UDPAddr
			switch cliConn.(type) {
			case *net.UDPConn:
				conn := cliConn.(*net.UDPConn)
				n, client, _ = conn.ReadFromUDP(buf)
			case *net.TCPConn:
				n, err = cliConn.Read(buf)
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
				log.Fatal("Could not decode IPv4 layer")
			}

			// 以太网层
			newEthLayer := &layers.Ethernet{
				SrcMAC:       nic.HwAddr(),
				DstMAC:       gatewayNIC.HwAddr(),
				EthernetType: layers.EthernetTypeIPv4,
			}

			// 修正 SrcIP
			ipLayer.SrcIP = nic.IPAddr()
			// 记录DstIP映射关系
			sktInfo := lan.SocketInfo{IP: ipLayer.SrcIP.String()}

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
				fmt.Printf("unsupport lan layer %s", packet.TransportLayer().LayerType())
				return
			}

			// TODO: LOCK优化
			lock.Lock()
			nat[sktInfo] = &trans.Conn{Conn: cliConn, UdpAddr: client}
			lock.Unlock()

			options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			buffer := gopacket.NewSerializeBuffer()

			if err := gopacket.SerializeLayers(buffer, options, newEthLayer, ipLayer, newTransLayer.(gopacket.SerializableLayer),
				gopacket.Payload(newTransLayer.LayerPayload())); err != nil {
				fmt.Println(err)
				return
			}
			// 转发给目标服务器
			if err := nicHandle.WritePacketData(buffer.Bytes()); err != nil {
				fmt.Println(err)
			}
		}
	}()

	// TODO: 手动重组
	// IP重组器
	// deFrag := ip4defrag.NewIPv4Defragmenter()
	// 监听remote回来的包
	receivePacketCh := gopacket.NewPacketSource(nicHandle, nicHandle.LinkType()).Packets()
	for {
		packet := <-receivePacketCh
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		sktInfo := lan.SocketInfo{IP: ipLayer.DstIP.String()}
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
			fmt.Println("unsupported layer")
		}

		// nat记录客户端连接
		lock.Lock()
		c, ok := nat[sktInfo]
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

		switch c.Conn.(type) {
		case *net.UDPConn:
			udpConn := c.Conn.(*net.UDPConn)
			if _, err := udpConn.WriteToUDP(packet.LinkLayer().LayerPayload(), c.UdpAddr); err != nil {
				fmt.Println(err)
				return
			}
		case *net.TCPConn:
			if _, err := c.Conn.Write(packet.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
