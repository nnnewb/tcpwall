# tcpwall

**目前还在开发中**

本项目是基于 [tcpwall](https://github.com/dushixiang/tcpwall) 基础上修改的弱网环境模拟工具，本机和指定 IP 通信时，随机产生
RST 报文给本机。

基本原理是调用 pcap 监听，拦截到和指定 IP:端口 通讯的报文时随机发送 RST 报文重置连接。

其他弱网环境模拟参数基本都可以用 [tc (8)](https://man7.org/linux/man-pages/man8/tc.8.html) 实现，唯独 RST 模拟工具不太好找。
所以干脆自己写一个。

## 使用

```
弱网环境模拟工具 0.0.1-dev (0000000) build 0000-00-00 00:00:00+00:00
Usage of ./tcpwall:

Example: ./tcpwall 192.168.2.5 9998

Options:
  -h, --help               show command line help
  -i, --interface string   network interface
      --number int         number of rst (default 1)
```

## LICENSE

GPL v2
