package main

import (
	"Ylang/internal/ip"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"log"
	"net"
	"time"
)

// NetDevice 网卡设备
type NetDevice struct {
	name     string
	ipAdders []*net.IPNet
	hwAddr   net.HardwareAddr
}

func main() {
	// 本地网卡名称
	upDevName := ""
	// 本地网卡设备
	var upDev *NetDevice
	// 本地网卡和上游server端的连接
	var upDevConn net.Conn

	// 监听目标主机IP和网关IP（ns中手动设置的值）
	targetIP := "10.0.0.2"
	// destIP -> targetDeviceMAC
	nat := make(map[string]net.HardwareAddr)
	targetGatewayIP := "10.0.0.1"
	// 服务端IP
	serverIP := "127.0.0.1:54321"

	// 先获取本机网卡设备和网关设备
	interfaces, _ := net.Interfaces()
	// 本机网卡设备
	var netDevices []*NetDevice
	for _, dev := range interfaces {
		dev := dev
		// interface up and not loopback
		if dev.Flags&net.FlagUp == 0 || dev.Flags&net.FlagLoopback != 0 {
			continue
		}

		adders, err := dev.Addrs()
		if err != nil {
			log.Println(err)
			continue
		}

		var ipAdders []*net.IPNet
		for _, addr := range adders {
			ipAdders = append(ipAdders, addr.(*net.IPNet))
		}
		netDevices = append(netDevices, &NetDevice{name: dev.Name, ipAdders: ipAdders, hwAddr: dev.HardwareAddr})
	}

	// 网关ip
	gatewayIp, _ := gateway.DiscoverGateway()

	if upDevName == "" {
		for _, device := range netDevices {
			for _, addr := range device.ipAdders {
				// 判断当前网卡和网关是不是一个网段
				if addr.Contains(gatewayIp) {
					upDev = device
					break
				}
			}

			if upDev != nil {
				break
			}
		}
	} else {
		for _, dev := range netDevices {
			if dev.name == upDevName {
				upDev = dev
				break
			}
		}
	}

	fmt.Println(upDev)

	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayDev, _ := findGatewayDev(upDev, gatewayIp)
	fmt.Println(gatewayDev.hwAddr)

	// 监听局域网目标主机的发送到本地upDev网卡流量
	handle, err := pcap.OpenLive(upDev.name, 65535, true, pcap.BlockForever)
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
				err := handleARPSpoofing(layer.(*layers.ARP), upDev, handle)
				if err != nil {
					fmt.Println(err)
				}
				continue
			}

			// 1. udp over tcp模式
			upDevConn, err = net.Dial("tcp", serverIP)
			if err != nil {
				fmt.Println(err)
			}
			// 通过tcp转发网络层数据（server端在facktcp模式需要手动重组，然后再分片发送到目标服务）
			if _, err := upDevConn.Write(packet.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}()

	for {
		// 接受server响应（也是网络层数据，最大65534）
		b := make([]byte, 1<<16-1)
		n, err := upDevConn.Read(b)
		if err != nil {
			fmt.Println(err)
		}
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		// ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipLayer == nil {
			log.Fatal("Could not decode IPv4 layer")
		}
		targetMAC := nat[ipLayer.SrcIP.String()]
		// 以太网层
		ethLayer := &layers.Ethernet{
			SrcMAC:       upDev.hwAddr,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		// 回传给目标主机（需要手动IP分片）
		frags := ip.FragmentIPPacket(ethLayer, ipLayer, 1500)
		for _, frag := range frags {
			if err := handle.WritePacketData(frag); err != nil {
				fmt.Println(err)
			}
		}
	}
}

// handleARPSpoofing 处理ARP欺骗，伪装网关响应ARP请求
func handleARPSpoofing(arpReq *layers.ARP, upDev *NetDevice, handle *pcap.Handle) error {

	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       upDev.hwAddr,
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
		SourceHwAddress:   upDev.hwAddr,
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

func findGatewayDev(upDev *NetDevice, gateway net.IP) (*NetDevice, error) {
	// 监听本机网卡数据包
	handle, _ := pcap.OpenLive(upDev.name, 65535, true, pcap.BlockForever)
	// 监听 dst=gateway 的 arpReply 请求
	if err := handle.SetBPFFilter(fmt.Sprintf("arp[6:2] = 2 && src host %s", gateway)); err != nil {
		return nil, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var sourceIp net.IP
	adds := upDev.ipAdders
	for _, addr := range adds {
		t := addr.IP.To4()
		if t != nil {
			sourceIp = t
			break
		}
	}

	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       upDev.hwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// ARP层
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeARP,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   upDev.hwAddr,
		SourceProtAddress: sourceIp.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    gateway.To4(),
	}

	// 组装数据
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, ethLayer, arpLayer)
	if err != nil {
		return nil, err
	}

	// 写入网卡
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	select {
	case <-time.After(3 * time.Second):
		return nil, errors.New("ARPRequest timeout")
	case packet := <-packetSource.Packets():
		arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		if arp.Operation == layers.ARPReply && gateway.Equal(arp.SourceProtAddress) {
			return &NetDevice{
				name:     "gateway",
				ipAdders: append(make([]*net.IPNet, 0), &net.IPNet{IP: gateway}),
				hwAddr:   arp.SourceHwAddress,
			}, nil
		}
	}
	return nil, errors.New("FindGatewayDev error")
}
