package main

import "C"
import (
	"flag"
	"fmt"
	"github.com/imlgw/ylang/api"
	"github.com/imlgw/ylang/internal/eth"
	"github.com/imlgw/ylang/tunnel/lan"
	"github.com/jackpal/gateway"
	"strconv"
)

var (
	apiPort = flag.Int("api", 8000, "Port for API server")
)

func main() {

	// 网关IP，暂时还没用到
	gatewayIp, _ := gateway.DiscoverGateway()

	if apiPort != nil {
		if err := api.Start("127.0.0.1:" + strconv.Itoa(*apiPort)); err != nil {
			fmt.Println("start api-server error", err)
			return
		}
	}

	for tun := range lan.Tunnels() {
		// 根据网关IP获取网关设备信息（MAC地址）
		gatewayNIC, _ := eth.FindGatewayNIC(tun.Nic(), tun.NicHandle(), gatewayIp)
		fmt.Println(gatewayNIC)
		go tun.ForwardLanDevice()
		go tun.BackwardLanDevice()
	}
}
