package utils

import (
	"fmt"
	"net"
)

func GetAvailableInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names, nil
}
