package ip4

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/samber/lo"
)

// FragmentIPPacket 对IP包进行分片
func FragmentIPPacket(ethLayer *layers.Ethernet, ipLayer *layers.IPv4, mtu uint16) [][]byte {
	// 计算分片数量
	numFragments := int(ipLayer.Length/mtu) + 1

	// 创建分片列表
	fragments := make([][]byte, numFragments)
	// 帧数据大小
	fragmentSize := mtu - 4*uint16(ipLayer.IHL)

	// 总长度
	totalLen := uint16(len(ipLayer.Contents))
	payload := ipLayer.Payload

	// 分片偏移量
	offset := uint16(0)

	// 逐个分片IP包
	for i := 0; i < numFragments; i++ {
		// 创建新的IP包
		newIP := *ipLayer

		// 设置分片相关字段
		newIP.Flags = layers.IPv4MoreFragments
		newIP.FragOffset = offset

		// 更新分片偏移量
		offset += fragmentSize / 8

		// 如果是最后一个分片，将标志位设置为0
		if i == numFragments-1 {
			newIP.Flags &= ^layers.IPv4MoreFragments
		}

		// 更新总长度
		newIP.Length = totalLen
		newIP.Payload = lo.Slice(payload, i*int(fragmentSize), (i+1)*int(fragmentSize))

		options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, options, ethLayer, &newIP)
		if err != nil {
			fmt.Println(err)
			return nil
		}

		// 添加到分片列表
		fragments[i] = buffer.Bytes()
	}

	return fragments
}
