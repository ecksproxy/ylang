## 简介

## todo

- [ ] facktcp
- [ ] UDPSpeeder
- [ ] 实现pcap2socks
- [ ] 多用户，密码
- [ ] GUI/Web 配置界面（底层链接新建/销毁不影响上层）
- [ ] 自定义应用层协议，延迟检测
- [ ] 局域网联机
- [ ] 加密传输
- [ ] 静默安装winpcap/libpcap


## 开发日志

整体架子搭建好之后开始调试，目前基本流程已通，初步试用马车能顺畅联机（家里是长城宽带，内网中的内网，马车无法联机）

1、Server转发包时端口没有固定，三次握手三个不同的端口。  
解决方案：直接使用原端口，不做修改

2、go build  
$ sudo apt-get install libpcap-dev
https://github.com/google/gopacket/issues/280

3、CGO_ENABLE  
编译问题，undefined
https://www.jianshu.com/p/bc78c32db030
https://github.com/google/gopacket/issues/629

4、nicHandle Close后重新打开卡死  
直接复用前面的，不close

5、GRO的问题  
开启gro，pcap会捕获到大包，后面可能收发都需要手动分片，作为TODO项处理

6、防火墙问题  
目前开发测试都是在本机上测试，server/client在本地mac上，始终不行，三次握手接收到syn+ack后就会直接发送rst重置连接。将server部署到远程的ubuntu上，问题解决，猜测是防火墙之类的问题，后面再深纠，先实现基本功能