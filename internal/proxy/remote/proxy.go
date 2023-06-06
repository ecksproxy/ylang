package remote

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imlgw/ylang/internal/config"
	"github.com/imlgw/ylang/internal/eth"
	"github.com/imlgw/ylang/internal/trans"
	"github.com/jackpal/gateway"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
)

var (
	tcpQueue   = make(chan net.Conn, 200)
	udpQueue   = make(chan *UDPPacket, 200)
	listenPort int
	nicName    string
	nat        map[trans.Socket]net.Conn
	lock       sync.Mutex
	localNic   *eth.Device
	gatewayNic *eth.Device
	// 网关ip
	gatewayIp, _ = gateway.DiscoverGateway()
)

type Proxy struct {
	tcpListen *TCPListener
	udpListen *UDPListener
}

func TCPIn() chan<- net.Conn {
	return tcpQueue
}

func UDPIn() chan<- *UDPPacket {
	return udpQueue
}

func NewRemoteProxy(cfg *config.Server) (*Proxy, error) {
	listenPort = cfg.ListenPort
	nicName = cfg.NicName
	nat = make(map[trans.Socket]net.Conn)
	// 获取指定nic设备
	localNic = eth.FindNIC(nicName)

	addr := fmt.Sprintf("%s:%d", "127.0.0.1", listenPort)
	tcpListen, err := NewTCPListener(addr, TCPIn())
	if err != nil {
		return nil, err
	}
	udpListen, err := NewUDPListener(addr, UDPIn())
	if err != nil {
		return nil, err
	}
	// 根据网关IP获取网关设备信息（MAC地址）
	gatewayNic, _ = eth.FindGatewayNIC(localNic, localNic.Handle(), gatewayIp)
	return &Proxy{
		tcpListen: tcpListen,
		udpListen: udpListen,
	}, nil
}

func (proxy *Proxy) Start() {
	// 监听所有进入的tcp/udp的包，除了client发来的包
	localNic.Listen(fmt.Sprintf("ip && ((tcp || udp) && (not dst port %d)) && (dst host %s)",
		listenPort, localNic.IPAddr().String()))
	go receive()
	go backward()

	// 后台运行
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}

func receive() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}
	go processTCP()
}

func backward() {
	receivePacketCh := gopacket.NewPacketSource(localNic.Handle(), localNic.Handle().LinkType()).Packets()
	for {
		pkt := <-receivePacketCh
		ipLayer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		skt := trans.Socket{IP: ipLayer.DstIP.String()}
		switch pkt.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			tcpLayer := pkt.TransportLayer().(*layers.TCP)
			skt.Port = uint16(tcpLayer.DstPort)
			skt.Protocol = uint8(layers.IPProtocolTCP)
		case layers.LayerTypeUDP:
			udpLayer := pkt.TransportLayer().(*layers.UDP)
			skt.Port = uint16(udpLayer.DstPort)
			skt.Protocol = uint8(layers.IPProtocolUDP)
		default:
			fmt.Println("unsupported")
		}

		// nat记录客户端连接
		lock.Lock()
		cli, ok := nat[skt]
		lock.Unlock()
		if !ok {
			continue
		}

		// IP包数据序列化后通过tcp回传给client
		options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(ipLayer.Payload)); err != nil {
			fmt.Println(err)
		}

		switch cli.(type) {
		case *UDPPacket:
			udpConn := cli.(*UDPPacket)
			if _, err := udpConn.pc.WriteTo(pkt.LinkLayer().LayerPayload(), udpConn.rAddr); err != nil {
				fmt.Println(err)
				return
			}
		case *net.TCPConn:
			if _, err := cli.Write(pkt.LinkLayer().LayerPayload()); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
