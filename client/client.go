package main

import (
	"Ylang/internal/eth"
	"Ylang/internal/ip4"
	"Ylang/internal/lan"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"log"
	"net"
)

func main() {
	// 本地网卡名称
	nicName := ""
	// 本地网卡设备
	var nic *eth.Device
	// 本地网卡和上游server端的连接
	var srvConn net.Conn

	// 监听目标主机IP和网关IP（ns中手动设置的值）
	targetIP := "10.0.0.2"
	// destIP -> targetDeviceMAC
	nat := make(map[string]*lan.ActiveHostConn)
	targetGatewayIP := "10.0.0.1"
	// 服务端IP
	serverIP := "192.168.1.102:54321"
	// 网关ip
	gatewayIp, _ := gateway.DiscoverGateway()

	// 1. udp over tcp模式
	srvConn, err := net.Dial("tcp", serverIP)
	if err != nil {
		fmt.Println(err)
	}

	nic = eth.FindNIC(nicName)
	fmt.Println(nic)

	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayNIC, _ := eth.FindGatewayNIC(nic, gatewayIp)
	fmt.Println(gatewayNIC)

	// 监听局域网目标主机的发送到本地nic网卡流量
	handle, err := pcap.OpenLive(nic.Name(), 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 局域网其他主机（ns）发出的tcp/udp包，以及arp请求的包
	if err := handle.SetBPFFilter(fmt.Sprintf("(ip && ((tcp || udp) && (src host %s))) || (arp[6:2] = 1 && dst host %s)",
		targetIP, targetGatewayIP)); err != nil {
		fmt.Println(err)
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// TODO: 通过tcp/udp/facktcp的方式转发到server端，或者现成的socks代理挂接

	go func() {
		for {
			// 监听局域网内设备
			packet := <-packetSource.Packets()
			ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			layer := packet.Layer(layers.LayerTypeARP)
			if layer != nil {
				// 如果是 ARPRequest 伪装层网关进行回应
				err := handleARPSpoofing(layer.(*layers.ARP), nic, handle)
				if err != nil {
					fmt.Println(err)
				}
				continue
			}

			ac := &lan.ActiveHostConn{Mac: ethernet.SrcMAC, IP: net.ParseIP(targetIP)}
			ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			switch ipv4.Protocol {
			case layers.IPProtocolTCP:
				ac.Port = uint16(packet.Layer(layers.LayerTypeTCP).(*layers.TCP).SrcPort)
			case layers.IPProtocolUDP:
				ac.Port = uint16(packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort)
			default:
				fmt.Printf("unsupported protocol: %s\n", ipv4.Protocol)
			}
			// full-cone NAT 记录destIP -> MAC地址映射
			nat[ipv4.DstIP.String()] = ac
			fmt.Println(ac)
			// 通过tcp转发网络层数据（server端在facktcp模式需要手动重组，然后再分片发送到目标服务）
			if _, err := srvConn.Write(packet.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}()

	for {
		// 接受server响应（也是网络层数据，最大65535）
		b := make([]byte, 1<<16-1)
		n, err := srvConn.Read(b)
		if err != nil {
			fmt.Println(err)
		}
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipLayer == nil {
			log.Fatal("Could not decode IPv4 layer")
		}
		// TODO: 修正数据包
		ac := nat[ipLayer.SrcIP.String()]
		// 以太网层
		ethLayer := &layers.Ethernet{
			SrcMAC:       nic.HwAddr(),
			DstMAC:       ac.Mac,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 修正 SrcIP/DstIP
		ipLayer.DstIP = net.ParseIP(targetIP)

		options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		buffer := gopacket.NewSerializeBuffer()

		// 修正传输层数据 SrcPort/DstPort
		switch packet.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := packet.TransportLayer().(*layers.TCP)
			if err != nil {
				fmt.Println(err)
				return
			}
			tcpLayer.DstPort = layers.TCPPort(ac.Port)
			// 设置伪头部
			if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}

			err = gopacket.SerializeLayers(buffer, options, tcpLayer, gopacket.Payload(tcpLayer.Payload))
			if err != nil {
				fmt.Println(err)
				return
			}

		case layers.LayerTypeUDP:
			udpLayer := packet.TransportLayer().(*layers.UDP)
			if err != nil {
				fmt.Println(err)
				return
			}
			udpLayer.DstPort = layers.UDPPort(ac.Port)
			// 设置伪头部
			if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				fmt.Println(err)
				return
			}

			err = gopacket.SerializeLayers(buffer, options, udpLayer, gopacket.Payload(udpLayer.Payload))
			if err != nil {
				fmt.Println(err)
				return
			}

		default:
			fmt.Printf("unsupport lan layer %s", packet.TransportLayer().LayerType())
			return
		}

		// 回传给目标主机（需要手动IP分片）
		frags := ip4.FragmentIPPacket(ethLayer, ipLayer, buffer.Bytes(), eth.MTU)
		for _, frag := range frags {
			if err := handle.WritePacketData(frag); err != nil {
				fmt.Println(err)
			}
		}
	}
}

// handleARPSpoofing 处理ARP欺骗，伪装网关响应ARP请求
func handleARPSpoofing(arpReq *layers.ARP, nic *eth.Device, handle *pcap.Handle) error {

	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       nic.HwAddr(),
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
		SourceHwAddress:   nic.HwAddr(),
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
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}
	return nil
}
