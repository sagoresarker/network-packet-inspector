package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/sagoresarker/network-packet-inspector/internal/models"
)

type Capturer struct {
	fd   int
	done chan struct{}
}

// const (
// 	AF_PACKET = 17     // Define AF_PACKET manually
// 	ETH_P_ALL = 0x0003 // Define ETH_P_ALL manually
// )

func NewCapturer(interfaceName string) (*Capturer, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to get interface: %v", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface: %v", err)
	}

	return &Capturer{fd: fd, done: make(chan struct{})}, nil
}

func (c *Capturer) Capture() <-chan models.RawPacket {
	packetChan := make(chan models.RawPacket)
	go func() {
		defer close(packetChan)
		for {
			select {
			case <-c.done:
				return
			default:
				buf := make([]byte, 65536)
				n, _, err := syscall.Recvfrom(c.fd, buf, 0)
				if err != nil {
					fmt.Printf("Error receiving packet: %v\n", err)
					continue
				}
				packetChan <- models.RawPacket{Data: buf[:n]}
			}
		}
	}()
	return packetChan
}

func (c *Capturer) Close() {
	close(c.done)
	syscall.Close(c.fd)
}

func htons(host uint16) uint16 {
	return binary.BigEndian.Uint16(binary.LittleEndian.AppendUint16(nil, host))
}
