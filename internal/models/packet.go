package models

import (
	"fmt"
	"time"
)

type RawPacket struct {
	Data []byte
}

type AnalyzedPacket struct {
	Timestamp        time.Time
	LinkLayer        LinkLayerInfo
	NetworkLayer     NetworkLayerInfo
	TransportLayer   TransportLayerInfo
	ApplicationLayer ApplicationLayerInfo
}

type LinkLayerInfo struct {
	Type           string
	SourceMAC      string
	DestinationMAC string
}

type NetworkLayerInfo struct {
	Type          string
	SourceIP      string
	DestinationIP string
}

type TransportLayerInfo struct {
	Type            string
	SourcePort      string
	DestinationPort string
}

type ApplicationLayerInfo struct {
	PayloadLength int
	Protocol      string
}

func (ap AnalyzedPacket) String() string {
	return fmt.Sprintf(`
--------------------
Timestamp: %s
Link Layer:
  Type: %s
  Source MAC: %s
  Destination MAC: %s

Network Layer:
  Type: %s
  Source IP: %s
  Destination IP: %s

Transport Layer:
  Type: %s
  Source Port: %s
  Destination Port: %s

Application Layer:
  Payload Length: %d bytes
  Protocol: %s
--------------------
`,
		ap.Timestamp.Format(time.RFC3339),
		ap.LinkLayer.Type, ap.LinkLayer.SourceMAC, ap.LinkLayer.DestinationMAC,
		ap.NetworkLayer.Type, ap.NetworkLayer.SourceIP, ap.NetworkLayer.DestinationIP,
		ap.TransportLayer.Type, ap.TransportLayer.SourcePort, ap.TransportLayer.DestinationPort,
		ap.ApplicationLayer.PayloadLength, ap.ApplicationLayer.Protocol)
}
