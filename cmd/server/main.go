package main

import (
	"flag"
	"fmt"
	"github.com/imlgw/ylang/internal/config"
	"github.com/imlgw/ylang/internal/proxy/remote"
)

var (
	listenPort = flag.Int("l", 54258, "Listen port for client")
	nicName    = flag.String("d", "", "nic device name")
)

func main() {
	proxy, err := remote.NewRemoteProxy(&config.Server{
		NicName:    *nicName,
		ListenPort: *listenPort,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	proxy.Start()
}
