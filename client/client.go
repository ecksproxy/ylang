package main

import (
	"Ylang/internal/eth"
	"Ylang/internal/ip4"
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
	nat := make(map[string]net.HardwareAddr)
	targetGatewayIP := "10.0.0.1"
	// 服务端IP
	serverIP := "127.0.0.1:54321"
	// 网关ip
	gatewayIp, _ := gateway.DiscoverGateway()

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
	if err := handle.SetBPFFilter(fmt.Sprintf("((tcp || udp) && (src host %s)) || (arp[6:2] = 1 && dst host %s)",
		targetIP, targetGatewayIP)); err != nil {
		fmt.Println(err)
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// TODO: 通过tcp/udp/facktcp的方式转发到server端，或者现成的socks代理挂接

	go func() {
		for {
			packet := <-packetSource.Packets()

			ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			// full-cone NAT 记录destIP -> MAC地址映射
			nat[ipv4.DstIP.String()] = ethernet.SrcMAC
			// 如果是 ARPRequest 伪装层网关进行回应
			layer := packet.Layer(layers.LayerTypeARP)
			if layer != nil {
				err := handleARPSpoofing(layer.(*layers.ARP), nic, handle)
				if err != nil {
					fmt.Println(err)
				}
				continue
			}

			// 1. udp over tcp模式
			srvConn, err = net.Dial("tcp", serverIP)
			if err != nil {
				fmt.Println(err)
			}
			// 通过tcp转发网络层数据（server端在facktcp模式需要手动重组，然后再分片发送到目标服务）
			if _, err := srvConn.Write(packet.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}()

	for {
		// 接受server响应（也是网络层数据，最大65534）
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
		targetMAC := nat[ipLayer.SrcIP.String()]
		// 以太网层
		ethLayer := &layers.Ethernet{
			SrcMAC:       nic.HwAddr(),
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 回传给目标主机（需要手动IP分片）
		frags := ip4.FragmentIPPacket(ethLayer, ipLayer, eth.MTU)
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
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeARP,
		HwAddressSize:   6,
		ProtAddressSize: 4,
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
