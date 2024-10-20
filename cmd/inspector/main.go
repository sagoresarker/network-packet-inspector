package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagoresarker/network-packet-inspector/internal/analyzer"
	"github.com/sagoresarker/network-packet-inspector/internal/capture"
	"github.com/sagoresarker/network-packet-inspector/pkg/utils"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	interfaceName := flag.String("interface", "", "Network interface to capture packets from")
	outputFile := flag.String("output", "", "File to save the output (optional)")
	listInterfaces := flag.Bool("list", false, "List available network interfaces")
	flag.Parse()

	if *listInterfaces {
		interfaces, err := utils.GetAvailableInterfaces()
		if err != nil {
			log.Fatalf("Failed to get network interfaces: %v", err)
		}
		fmt.Println("Available network interfaces:")
		for _, iface := range interfaces {
			fmt.Println("-", iface)
		}
		return
	}

	if *interfaceName == "" {
		log.Fatal("Please specify a network interface using the -interface flag")
	}

	capturer, err := capture.NewCapturer(*interfaceName)
	if err != nil {
		log.Fatalf("Failed to create capturer: %v", err)
	}
	defer capturer.Close()

	analyzer := analyzer.NewAnalyzer()

	var output *os.File
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer output.Close()
	}

	fmt.Printf("Starting packet capture on interface %s...\n", *interfaceName)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal. Shutting down...")
		capturer.Close()
		os.Exit(0)
	}()

	for packet := range capturer.Capture() {
		analyzedPacket := analyzer.Analyze(packet)
		if output != nil {
			_, err := fmt.Fprintln(output, analyzedPacket)
			if err != nil {
				log.Printf("Error writing to output file: %v", err)
			}
		} else {
			fmt.Println(analyzedPacket)
		}
	}
}
