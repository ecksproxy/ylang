package main

import (
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
	devName := ""
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

	var upDev *NetDevice
	if devName == "" {
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
			if dev.name == devName {
				upDev = dev
				break
			}
		}
	}

	fmt.Println(upDev)

	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayDev, _ := FindGatewayDev(upDev, gatewayIp)
	fmt.Println(gatewayDev.hwAddr)

	// 监听局域网目标主机的流量，通过tcp/udp/facktcp的方式转发到server端
}

func FindGatewayDev(upDev *NetDevice, gateway net.IP) (*NetDevice, error) {
	// 监听本机网卡数据包
	handle, _ := pcap.OpenLive(upDev.name, 65535, true, pcap.BlockForever)
	// 监听 dst=gateway 的 arpReply 请求
	if err := handle.SetBPFFilter(fmt.Sprintf("arp[6:2] = 2 && src host %s", gateway)); err != nil {
		return nil, err
	}

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
