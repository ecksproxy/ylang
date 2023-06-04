package main

import (
	"flag"
	"fmt"
	"github.com/imlgw/ylang/config"
	"github.com/imlgw/ylang/tunnel/wan"
)

var (
	listenPort = flag.Int("l", 54258, "Listen port for client")
	nicName    = flag.String("d", "", "nic device name")
)

func main() {

	tunnel, err := wan.NewTunnel(&config.Server{
		NicName:    *nicName,
		ListenPort: *listenPort,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	wan.Tunnels() <- tunnel
	for tun := range wan.Tunnels() {
		go tun.ForwardClientData()
		go tun.BackwardServerData()
	}
}
