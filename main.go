package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

var (
	VERSION  string = "0.0.1-dev"
	REVISION string = "0000000"
	BUILD    string = "0000-00-00 00:00:00+00:00"

	options struct {
		Help    bool   // 显示帮助信息
		Version bool   // 显示版本信息
		Link    string // 监听的连接
		Number  int    // 确定 rst 的 seq 要跨几个 window
	}
)

func init() {
	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "tcpwall %s (%s) build %s\n", VERSION, REVISION, BUILD)
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s: %s [OPTIONS...] IP PORT \n", os.Args[0], os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "\nExample: %s 192.168.2.5 9998\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}
	pflag.BoolVarP(&options.Help, "help", "h", false, "show command line help")
	pflag.BoolVarP(&options.Version, "version", "v", false, "show version information")
	pflag.StringVarP(&options.Link, "interface", "i", "", "network interface")
	pflag.IntVar(&options.Number, "number", 1, "number of rst")
}

func wall(ctx context.Context, link string, host net.IP, port int, rate int) error {
	log.Printf("open link: %s", link)
	handle, err := pcap.OpenLive(link, int32(65535), true, -1*time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and dst host %s and dst port %d", host, port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for {
		var pkt gopacket.Packet
		select {
		case <-ctx.Done():
			return nil
		case pkt = <-packets:
			if pkt == nil {
				return nil
			}
		}

		// 随机出现 rst
		if rand.Int()%10000 <= rate {
			continue
		}

		var src, dst net.IP
		nl := pkt.NetworkLayer()
		switch nl.(type) {
		case *layers.IPv4, *layers.IPv6:
			sep, dep := nl.NetworkFlow().Endpoints()
			src, dst = net.IP(sep.Raw()), net.IP(dep.Raw())
		default:
			log.Printf("ignore packet: unexpected network layer %s", nl.LayerType())
			continue
		}

		var sport, dport uint16
		var ack uint32
		var window uint16
		if tcp, ok := pkt.TransportLayer().(*layers.TCP); ok {
			if tcp.SYN || tcp.FIN || tcp.RST {
				continue
			}

			sport = uint16(tcp.SrcPort)
			dport = uint16(tcp.DstPort)
			ack = tcp.Ack
		}

		var seq = uint64(ack)
		for i := 0; i < options.Number; i++ {
			if seq+uint64(i)*uint64(window) > math.MaxUint32 {
				seq = 0
			} else {
				seq += uint64(i) * uint64(window)
			}

			err := SendRST(dst.To4(), src.To4(), dport, sport, uint32(seq), handle)
			if err != nil {
				return err
			}
		}
	}
}

func SendRST(src, dst net.IP, sport, dport uint16, seq uint32, handle *pcap.Handle) error {
	log.Printf("send %s:%d > %s:%d [RST] seq %d", src, sport, dst, dport, seq)

	// IPv6 is not supported
	if src.To4() == nil || dst.To4() == nil {
		return fmt.Errorf("IPv6 is not supported")
	}

	networkLayer := layers.IPv4{
		SrcIP:    src,
		DstIP:    dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	transportLayer := layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     seq,
		RST:     true,
	}

	if err := transportLayer.SetNetworkLayerForChecksum(&networkLayer); err != nil {
		return err
	}

	serializeBuffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(serializeBuffer, serializeOptions, &networkLayer, &transportLayer); err != nil {
		return err
	}

	err := handle.WritePacketData(serializeBuffer.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	pflag.Parse()
	if options.Help {
		pflag.Usage()
		return
	}

	if len(options.Link) == 0 {
		devs := must(pcap.FindAllDevs())
		if len(devs) == 0 {
			log.Printf("interface is not found,please select the interface manually.")
			os.Exit(1)
		}
		log.Printf("select interface %s", devs[0].Name)
		options.Link = devs[0].Name
	}

	if pflag.NArg() < 2 {
		log.Printf("usage: %s <peer> <port>", os.Args[0])
		os.Exit(1)
	}

	ip := net.ParseIP(pflag.Arg(0))
	port, err := strconv.ParseInt(pflag.Arg(1), 10, 32)
	if err != nil {
		log.Printf("invalid port: %s", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg := &sync.WaitGroup{}
	go func(wg *sync.WaitGroup) {
		log.Println(wall(ctx, options.Link, ip, int(port), 10))
	}(wg)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Printf("graceful shutdown ...")
	cancel()
	wg.Wait()
	log.Printf("goodbye.")
}
