package main

import (
	"flag"
)

var (
	listenPort = flag.Int("l", 54258, "Listen port for client")
	nicName    = flag.String("d", "", "nic device name")
)

func main() {

	// tunnel, err := remote.NewRemoteProxy(&config.Server{
	// 	NicName:    *nicName,
	// 	ListenPort: *listenPort,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	//
	// remote.Tunnels() <- tunnel
	// for tun := range remote.Tunnels() {
	// 	go tun.ForwardClientData()
	// 	go tun.BackwardServerData()
	// }
}
