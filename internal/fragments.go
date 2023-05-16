package internal

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
	"unsafe"
)

const (
	ETH_HEADER_SIZE = 14
	IP_HEADER_SIZE  = 20
	MTU             = 1500
)

// IPHeader represents the IP header structure
type IPHeader struct {
	VersionIHL    uint8
	TOS           uint8
	TotalLength   uint16
	ID            uint16
	FlagsFragOff  uint16
	TTL           uint8
	Protocol      uint8
	Checksum      uint16
	SourceIP      uint32
	DestinationIP uint32
}

// FragmentIPPacket takes an IP packet and fragments it into smaller packets based on MTU
func FragmentIPPacket(packet []byte) [][]byte {
	packetSize := len(packet)
	header := (*IPHeader)(unsafe.Pointer(&packet[ETH_HEADER_SIZE]))

	// Calculate the payload size excluding the IP header
	payloadSize := packetSize - ETH_HEADER_SIZE - IP_HEADER_SIZE
	if payloadSize <= MTU {
		// Packet doesn't need fragmentation
		return [][]byte{packet}
	}

	// Calculate the number of fragments required
	numFragments := payloadSize / MTU
	if payloadSize%MTU != 0 {
		numFragments++
	}

	fragments := make([][]byte, numFragments)
	offset := 0

	for i := 0; i < numFragments; i++ {
		fragmentSize := MTU - IP_HEADER_SIZE
		if i == numFragments-1 {
			fragmentSize = payloadSize - (MTU-IP_HEADER_SIZE)*i
		}

		fragment := make([]byte, ETH_HEADER_SIZE+IP_HEADER_SIZE+fragmentSize)
		copy(fragment, packet[:ETH_HEADER_SIZE])

		// Update the total length and fragment offset fields in the IP header
		fragmentHeader := (*IPHeader)(unsafe.Pointer(&fragment[ETH_HEADER_SIZE]))
		fragmentHeader.TotalLength = htons(uint16(fragmentSize + IP_HEADER_SIZE))
		fragmentHeader.FlagsFragOff = htons(uint16(i*fragmentSize/8) | 0x2000) // Set the More Fragments flag if there are more fragments

		copy(fragment[ETH_HEADER_SIZE+IP_HEADER_SIZE:], packet[ETH_HEADER_SIZE+IP_HEADER_SIZE+offset:ETH_HEADER_SIZE+IP_HEADER_SIZE+offset+fragmentSize])
		fragments[i] = fragment
		offset += fragmentSize
	}

	return fragments
}

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	packetData := buffer[:n]
	packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipLayer == nil {
		log.Fatal("Could not decode IPv4 layer")
	}

	fragments := fragmentIPPacket(ipLayer)
	fmt.Println(fragments)
}

// 对IP包进行分片
func fragmentIPPacket(ip *layers.IPv4) []*layers.IPv4 {
	// 计算分片数量
	numFragments := int(ip.Length/MTU) + 1

	// 创建分片列表
	fragments := make([]*layers.IPv4, numFragments)

	// 分片偏移量
	offset := uint16(0)

	// 逐个分片IP包
	for i := 0; i < numFragments; i++ {
		// 创建新的IP包
		fragment := *ip

		// 设置分片相关字段
		fragment.Flags = layers.IPv4MoreFragments
		fragment.FragOffset = offset

		// 更新分片偏移量
		offset += uint16(MTU / 8)

		// 如果是最后一个分片，将标志位设置为0
		if i == numFragments-1 {
			fragment.Flags &= ^layers.IPv4MoreFragments
		}

		// 更新总长度
		fragment.Length = uint16(len(fragment.Contents))

		// 添加到分片列表
		fragments[i] = &fragment
	}

	return fragments
}

// 将分片发送到网卡
func sendFragmentsToNIC(fragments []*layers.IPv4) {
	// 获取网卡
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}
	// 打开网卡
	conn, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// 获取网卡的硬件地址
	hwAddr := iface.HardwareAddr

	// 获取目标IP地址
	dstIP := net.ParseIP("192.168.0.100")

	// 发送每个分片到目标IP地址
	for _, fragment := range fragments {
		// 设置源和目的MAC地址
		eth := &layers.Ethernet{
			SrcMAC:       hwAddr,
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 设置目的MAC地址
			EthernetType: layers.EthernetTypeIPv4,
		}

		// 将Ethernet帧和IP包数据合并
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(buffer, opts, eth, fragment)
		if err != nil {
			log.Fatal(err)
		}

		// 发送数据到目标IP地址
		err = conn.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatal(err)
		}

		// 等待一段时间，以便分片到达目标主机
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("分片发送完成")
}
