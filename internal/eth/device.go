package eth

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

const MTU = 1500

// Device 网卡设备
type Device struct {
	name     string
	ipAdders []*net.IPNet
	hwAddr   net.HardwareAddr
}

func (d *Device) Name() string {
	return d.name
}

func (d *Device) IPNetAdders() []*net.IPNet {
	return d.ipAdders
}

func (d *Device) HwAddr() net.HardwareAddr {
	return d.hwAddr
}

func (d *Device) IPAddr() net.IP {
	var sourceIp net.IP
	adds := d.ipAdders
	for _, addr := range adds {
		t := addr.IP.To4()
		if t != nil {
			sourceIp = t
			break
		}
	}
	return sourceIp
}

// FindLocalNICs 获取本机网卡设备
func FindLocalNICs() []*Device {
	// 先获取本机网卡设备和网关设备
	interfaces, _ := net.Interfaces()
	// 本机网卡设备
	var netDevices []*Device
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
		netDevices = append(netDevices, &Device{name: dev.Name, ipAdders: ipAdders, hwAddr: dev.HardwareAddr})
	}
	return netDevices
}

// FindNIC 获取指定网卡设备
func FindNIC(devName string) *Device {
	// 本地网卡设备
	var upDev *Device

	netDevices := FindLocalNICs()

	if devName == "" {
		// 网关ip
		gatewayIp, _ := gateway.DiscoverGateway()
		for _, device := range netDevices {
			for _, addr := range device.IPNetAdders() {
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
			if dev.Name() == devName {
				upDev = dev
				break
			}
		}
	}
	return upDev
}

// FindGatewayNIC 获取网关网卡设备
func FindGatewayNIC(upDev *Device, gateway net.IP) (*Device, error) {
	// 监听本机网卡数据包
	handle, _ := pcap.OpenLive(upDev.name, 65535, true, pcap.BlockForever)
	// 监听 dst=gateway 的 arpReply 请求
	if err := handle.SetBPFFilter(fmt.Sprintf("arp[6:2] = 2 && src host %s", gateway)); err != nil {
		return nil, err
	}
	// defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
		SourceProtAddress: upDev.IPAddr(),
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
			return &Device{
				name:     "gateway",
				ipAdders: append(make([]*net.IPNet, 0), &net.IPNet{IP: gateway}),
				hwAddr:   arp.SourceHwAddress,
			}, nil
		}
	}
	return nil, errors.New("FindGatewayDev error")
}
