package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sagoresarker/network-packet-inspector/internal/models"
)

type Capturer struct {
	handle *pcap.Handle
	done   chan struct{}
}

func NewCapturer(interfaceName string) (*Capturer, error) {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %v", interfaceName, err)
	}
	return &Capturer{handle: handle, done: make(chan struct{})}, nil
}

func (c *Capturer) Capture() <-chan models.RawPacket {
	packetChan := make(chan models.RawPacket)
	go func() {
		defer close(packetChan)
		packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
		for {
			select {
			case <-c.done:
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					log.Printf("Error capturing packet: %v", err)
					continue
				}
				packetChan <- models.RawPacket{Packet: packet}
			}
		}
	}()
	return packetChan
}

func (c *Capturer) Close() {
	close(c.done)
	c.handle.Close()
}
