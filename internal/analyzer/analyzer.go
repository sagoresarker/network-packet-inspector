package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sagoresarker/network-packet-inspector/internal/models"
)

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(rawPacket models.RawPacket) models.AnalyzedPacket {
	analyzed := models.AnalyzedPacket{
		Timestamp: time.Now(),
	}

	// Analyze Link Layer
	analyzed.LinkLayer = a.analyzeLinkLayer(rawPacket.Data)

	// Analyze Network Layer
	if len(rawPacket.Data) > 14 {
		analyzed.NetworkLayer = a.analyzeNetworkLayer(rawPacket.Data[14:])
	}

	// Analyze Transport Layer
	if len(rawPacket.Data) > 34 {
		analyzed.TransportLayer = a.analyzeTransportLayer(rawPacket.Data[34:])
	}

	// Analyze Application Layer
	if len(rawPacket.Data) > 54 {
		analyzed.ApplicationLayer = a.analyzeApplicationLayer(rawPacket.Data[54:])
	}

	return analyzed
}

func (a *Analyzer) analyzeLinkLayer(data []byte) models.LinkLayerInfo {
	return models.LinkLayerInfo{
		Type:           "Ethernet",
		SourceMAC:      net.HardwareAddr(data[6:12]).String(),
		DestinationMAC: net.HardwareAddr(data[0:6]).String(),
	}
}

func (a *Analyzer) analyzeNetworkLayer(data []byte) models.NetworkLayerInfo {
	return models.NetworkLayerInfo{
		Type:          "IPv4",
		SourceIP:      net.IP(data[12:16]).String(),
		DestinationIP: net.IP(data[16:20]).String(),
	}
}

func (a *Analyzer) analyzeTransportLayer(data []byte) models.TransportLayerInfo {
	protocol := data[9]
	var typ string
	switch protocol {
	case 6:
		typ = "TCP"
	case 17:
		typ = "UDP"
	default:
		typ = fmt.Sprintf("Unknown (%d)", protocol)
	}

	return models.TransportLayerInfo{
		Type:            typ,
		SourcePort:      fmt.Sprintf("%d", binary.BigEndian.Uint16(data[0:2])),
		DestinationPort: fmt.Sprintf("%d", binary.BigEndian.Uint16(data[2:4])),
	}
}

func (a *Analyzer) analyzeApplicationLayer(data []byte) models.ApplicationLayerInfo {
	return models.ApplicationLayerInfo{
		PayloadLength: len(data),
		Protocol:      "Unknown",
	}
}
