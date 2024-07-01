package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type ifreq struct {
	Name  [syscall.IFNAMSIZ]byte
	Flags uint16
}

func readPackets(file *os.File) {
	buf := make([]byte, 1500)

	for {
		n, err := file.Read(buf)
		if err != nil {
			fmt.Println("读取数据失败", err)
			return
		}

		if n > 0 {
			processPacket(buf[:n])
		}
	}
}

func processPacket(packet []byte) {
	version := packet[0] >> 4
	if len(packet) < 20 {
		fmt.Println("数据包过短")
		return
	}
	switch version {
	case 4:
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			fmt.Println("解析IPV4数据包错误", err)
			return
		}

		fmt.Printf("Src: %s, Dst: %s	", header.Src, header.Dst)

		// 根据协议解析传输层
		switch header.Protocol {
		case 6: // TCP
			handleTCPPacket(packet[header.Len:])
		case 17: // UDP
			handleUDPPacket(packet[header.Len:])
		default:
			fmt.Println("未知协议类型")
		}
	case 6:
		header, err := ipv6.ParseHeader(packet)
		if err != nil {
			fmt.Println("解析IPv6数据包失败", err)
			return
		}

		fmt.Printf("Src: %s, Dst: %s	", header.Src, header.Dst)

		// 根据协议解析传输层
		switch header.NextHeader {
		case 6: // TCP
			handleTCPPacket(packet[ipv6.HeaderLen:])
		case 17: // UDP
			handleUDPPacket(packet[ipv6.HeaderLen:])
		default:
			fmt.Println("未知协议类型")
		}
	default:
		fmt.Println("未知数据包格式")
	}
}

func handleTCPPacket(packet []byte) {
	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])

	fmt.Printf("protocol:TCP Src Port: %d, Dst Port: %d\n", srcPort, dstPort)
}

func handleUDPPacket(packet []byte) {
	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])
	fmt.Printf("protocol:UDP Src Port: %d, Dst Port: %d\n", srcPort, dstPort)
}

func main() {
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("打开tun文件失败", err)
		return
	}
	defer tun.Close()
	var ifr ifreq
	copy(ifr.Name[:], "tun0")
	ifr.Flags = IFF_TUN | IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tun.Fd(), TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		fmt.Println("创建tun接口失败")
		return
	}
	cmd := exec.Command("ip", "link", "set", "dev", "tun0", "up")
	err = cmd.Run()
	if err != nil {
		fmt.Println("设置tun0接口失败", err)
		return
	}
	fmt.Println("正在抓取")
	readPackets(tun)
}
