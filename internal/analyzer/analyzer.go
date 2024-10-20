package analyzer

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sagoresarker/network-packet-inspector/internal/models"
)

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(rawPacket models.RawPacket) models.AnalyzedPacket {
	packet := rawPacket.Packet
	analyzed := models.AnalyzedPacket{
		Timestamp: time.Now(),
	}

	// Analyze Link Layer
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		analyzed.LinkLayer = models.LinkLayerInfo{
			Type:           linkLayer.LayerType().String(),
			SourceMAC:      linkLayer.LinkFlow().Src().String(),
			DestinationMAC: linkLayer.LinkFlow().Dst().String(),
		}
	}

	// Analyze Network Layer
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		analyzed.NetworkLayer = models.NetworkLayerInfo{
			Type:          networkLayer.LayerType().String(),
			SourceIP:      networkLayer.NetworkFlow().Src().String(),
			DestinationIP: networkLayer.NetworkFlow().Dst().String(),
		}
	}

	// Analyze Transport Layer
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		analyzed.TransportLayer = models.TransportLayerInfo{
			Type:            transportLayer.LayerType().String(),
			SourcePort:      transportLayer.TransportFlow().Src().String(),
			DestinationPort: transportLayer.TransportFlow().Dst().String(),
		}
	}

	// Analyze Application Layer
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		analyzed.ApplicationLayer = models.ApplicationLayerInfo{
			PayloadLength: len(applicationLayer.Payload()),
			Protocol:      a.determineApplicationProtocol(packet),
		}
	}

	return analyzed
}

func (a *Analyzer) determineApplicationProtocol(packet gopacket.Packet) string {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		switch {
		case tcp.SrcPort == 80 || tcp.DstPort == 80:
			return "HTTP"
		case tcp.SrcPort == 443 || tcp.DstPort == 443:
			return "HTTPS"
		case tcp.SrcPort == 22 || tcp.DstPort == 22:
			return "SSH"
		}
	}
	return "Unknown"
}
