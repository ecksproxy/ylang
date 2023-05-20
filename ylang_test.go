package t_test

import (
	"Ylang/internal/eth"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"testing"
)

func TestPcap(t *testing.T) {
	handle, err := pcap.OpenLive("en0", 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
	}

	nic := eth.FindNIC("en0")

	// eth.dst == 00:00:00:00:00:00
	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       nic.HwAddr(),
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	data := make([]byte, 2000)
	data[1499] = 1

	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
	// 组装数据
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, ethLayer, packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4))

	err = handle.WritePacketData(data)
	if err != nil {
		fmt.Println(123)
		fmt.Println(err)
	}
}
