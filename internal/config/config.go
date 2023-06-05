package config

type Client struct {
	NicName         string `json:"nic_name"`
	Mode            string `json:"mode"`
	TargetIP        string `json:"target_ip"`
	TargetGatewayIP string `json:"target_gateway_ip"`
	ServerIP        string `json:"server_ip"`
	ServerPort      int    `json:"server_port"`
}

type Server struct {
	ListenPort int    `json:"listen_port"`
	NicName    string `json:"nic_name"`
}
