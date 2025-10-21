package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var filePath string
	var srcIPStr string
	var dstIPStr string
	var srcPortInt int
	var dstPortInt int
	var url string
	var iface string

	flag.StringVar(&filePath, "f", "", "file to inject")
	flag.StringVar(&srcIPStr, "srcip", "", "source IP")
	flag.StringVar(&dstIPStr, "dstip", "", "destination IP")
	flag.IntVar(&srcPortInt, "srcport", 0, "source port")
	flag.IntVar(&dstPortInt, "dstport", 0, "destination port")
	flag.StringVar(&url, "url", "", "URL text")
	flag.StringVar(&iface, "i", "", "interface to inject the packets onto")
	flag.Parse()

	if filePath == "" || srcIPStr == "" || dstIPStr == "" || srcPortInt == 0 || dstPortInt == 0 || url == "" || iface == "" {
		log.Fatal("All arguments are required")
	}

	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		log.Fatalf("File does not exist: %v", err)
	}

	// Read file content
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Parse IPs
	srcIP := net.ParseIP(srcIPStr).To4()
	dstIP := net.ParseIP(dstIPStr).To4()
	if srcIP == nil || dstIP == nil {
		log.Fatal("Invalid IP addresses")
	}

	// Ports
	srcPort := layers.TCPPort(srcPortInt)
	dstPort := layers.TCPPort(dstPortInt)

	// Assign fake MAC addresses for client and server
	clientMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

	// Random ISNs
	rand.Seed(time.Now().UnixNano())
	clientISN := uint32(rand.Int31())
	serverISN := uint32(rand.Int31())

	clientSeq := clientISN + 1
	serverSeq := serverISN + 1

	// Open pcap handle for injection
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening pcap handle: %v", err)
	}
	defer handle.Close()

	// Helper function to send a packet
	sendPacket := func(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, tcp layers.TCP, payload []byte) {
		eth := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)
		err := gopacket.SerializeLayers(buf, opts, &eth, &ip4, &tcp, gopacket.Payload(payload))
		if err != nil {
			log.Fatalf("Error serializing packet: %v", err)
		}
		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			log.Fatalf("Error writing packet: %v", err)
		}
	}

	// Packet 1: SYN (Client -> Server)
	tcpSyn := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientISN,
		SYN:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpSyn, nil)

	// Packet 2: SYN-ACK (Server -> Client)
	tcpSynAck := layers.TCP{
		SrcPort: dstPort,
		DstPort: srcPort,
		Seq:     serverISN,
		Ack:     clientISN + 1,
		SYN:     true,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpSynAck, nil)

	// Packet 3: ACK (Client -> Server)
	tcpAck := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientISN + 1,
		Ack:     serverISN + 1,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpAck, nil)

	// HTTP GET request
	host := dstIPStr
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: test\r\nAccept: */*\r\nConnection: close\r\n\r\n", url, host)
	reqBytes := []byte(request)

	// Packet 4: PSH ACK with HTTP request (Client -> Server)
	tcpReq := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientSeq,
		Ack:     serverSeq,
		ACK:     true,
		PSH:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpReq, reqBytes)
	clientSeq += uint32(len(reqBytes))

	// Packet 5: ACK for request (Server -> Client)
	tcpAckReq := layers.TCP{
		SrcPort: dstPort,
		DstPort: srcPort,
		Seq:     serverSeq,
		Ack:     clientSeq,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpAckReq, nil)

	// HTTP response header
	contentLength := len(fileContent)
	responseHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", contentLength)
	headerBytes := []byte(responseHeader)

	// Packet 6: PSH ACK with response header (Server -> Client)
	tcpHeader := layers.TCP{
		SrcPort: dstPort,
		DstPort: srcPort,
		Seq:     serverSeq,
		Ack:     clientSeq,
		ACK:     true,
		PSH:     true,
		Window:  65535,
	}
	sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpHeader, headerBytes)
	serverSeq += uint32(len(headerBytes))

	// Send file content in chunks (max 1400 bytes per packet for realism)
	chunkSize := 1400
	for i := 0; i < len(fileContent); i += chunkSize {
		end := i + chunkSize
		if end > len(fileContent) {
			end = len(fileContent)
		}
		chunk := fileContent[i:end]
		psh := (end == len(fileContent)) // PSH on last chunk

		tcpChunk := layers.TCP{
			SrcPort: dstPort,
			DstPort: srcPort,
			Seq:     serverSeq,
			Ack:     clientSeq,
			ACK:     true,
			PSH:     psh,
			Window:  65535,
		}
		sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpChunk, chunk)
		serverSeq += uint32(len(chunk))
	}

	// Packet: ACK for all data (Client -> Server)
	tcpAckData := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientSeq,
		Ack:     serverSeq,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpAckData, nil)

	// Packet: FIN ACK (Server -> Client)
	tcpFinServer := layers.TCP{
		SrcPort: dstPort,
		DstPort: srcPort,
		Seq:     serverSeq,
		Ack:     clientSeq,
		FIN:     true,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpFinServer, nil)
	serverSeq += 1

	// Packet: ACK for server FIN (Client -> Server)
	tcpAckFinServer := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientSeq,
		Ack:     serverSeq,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpAckFinServer, nil)

	// Packet: FIN ACK (Client -> Server)
	tcpFinClient := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     clientSeq,
		Ack:     serverSeq,
		FIN:     true,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(clientMAC, serverMAC, srcIP, dstIP, srcPort, dstPort, tcpFinClient, nil)
	clientSeq += 1

	// Packet: ACK for client FIN (Server -> Client)
	tcpAckFinClient := layers.TCP{
		SrcPort: dstPort,
		DstPort: srcPort,
		Seq:     serverSeq,
		Ack:     clientSeq,
		ACK:     true,
		Window:  65535,
	}
	sendPacket(serverMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, tcpAckFinClient, nil)

	fmt.Println("Packets injected successfully")
}
