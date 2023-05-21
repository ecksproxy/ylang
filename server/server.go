package main

import (
	"Ylang/internal/eth"
	"Ylang/internal/ip4"
	"Ylang/internal/lan"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
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
	// 本地网卡和下游client端的连接
	var cliConn net.Conn
	var port = 54321
	var nat = make(map[string]string)
	// 获取指定nic设备
	nic = eth.FindNIC(nicName)

	// 网关ip
	gatewayIp, _ := gateway.DiscoverGateway()
	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayNIC, _ := eth.FindGatewayNIC(nic, gatewayIp)

	// 监听nic设备，通过NIC设备发送到目标服务器
	nicHandle, err := pcap.OpenLive(nic.Name(), 65535, true, pcap.BlockForever)
	// 监听所有tcp/udp的包，除了client发来的包
	err = nicHandle.SetBPFFilter(fmt.Sprintf("ip && ((tcp || udp) && (not dst port %d))", port))
	if err != nil {
		fmt.Println(err)
	}

	// 监听客户端请求，转发给目标服务
	go func() {
		listen, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   nic.IPAddr(),
			Port: port,
		})
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(nic.IPAddr())
		// TODO: 多客户端
		cliConn, err = listen.AcceptTCP()
		fmt.Printf("connect from: %s \n", cliConn.RemoteAddr().String())

		for {
			// tcp包payload是ip包数据，最大65535
			buf := make([]byte, 65535)
			n, err := cliConn.Read(buf)
			if err != nil {
				fmt.Println(err)
			}

			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
			ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if ipLayer == nil {
				log.Fatal("Could not decode IPv4 layer")
			}

			// 记录DstIP映射关系
			nat[ipLayer.DstIP.String()] = gatewayNIC.HwAddr().String()
			// 以太网层
			newEthLayer := &layers.Ethernet{
				SrcMAC:       nic.HwAddr(),
				DstMAC:       gatewayNIC.HwAddr(),
				EthernetType: layers.EthernetTypeIPv4,
			}

			// 修正 SrcIP
			ipLayer.SrcIP = nic.IPAddr()
			// 构建传输层数据
			switch packet.TransportLayer().LayerType() {
			case layers.LayerTypeTCP:
				tcpLayer := packet.TransportLayer().(*layers.TCP)
				port, err := lan.FindSrcPort(packet)
				if err != nil {
					fmt.Println(err)
					return
				}
				// 修正 SrcPort
				tcpLayer.SrcPort = layers.TCPPort(port)
				// 设置伪头部
				if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
					fmt.Println(err)
					return
				}

			case layers.LayerTypeUDP:
				udpLayer := packet.TransportLayer().(*layers.UDP)
				port, err := lan.FindSrcPort(packet)
				if err != nil {
					fmt.Println(err)
					return
				}
				// 修正源端口
				udpLayer.SrcPort = layers.UDPPort(port)
				// 设置伪头部
				if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
					fmt.Println(err)
					return
				}
			default:
				fmt.Printf("unsupport lan layer %s", packet.TransportLayer().LayerType())
				return
			}

			// IP包分片
			frags := ip4.FragmentIPPacket(newEthLayer, ipLayer, ipLayer.Payload, eth.MTU)
			for _, frag := range frags {
				// 转发给目标服务器
				if err := nicHandle.WritePacketData(frag); err != nil {
					fmt.Println(err)
				}
			}
		}
	}()

	// TODO: 手动重组
	// IP重组器
	deFrag := ip4defrag.NewIPv4Defragmenter()
	// 监听remote回来的包
	receivePacketCh := gopacket.NewPacketSource(nicHandle, nicHandle.LinkType()).Packets()
	for {
		packet := <-receivePacketCh
		ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		_, ok := nat[ipLayer.SrcIP.String()]
		if !ok {
			continue
		}
		fmt.Printf("recevie data: %s \n", packet.String())
		// 重组后回传给 client
		in, err := deFrag.DefragIPv4(ipLayer)
		if err != nil {
			fmt.Println(err)
		}

		// not complete
		if in == nil {
			continue
		}

		// IP包数据序列化后通过tcp回传给client
		options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, options, in, gopacket.Payload(in.Payload)); err != nil {
			fmt.Println(err)
		}
		if _, err := cliConn.Write(buffer.Bytes()); err != nil {
			fmt.Println(err)
		}
	}
}
