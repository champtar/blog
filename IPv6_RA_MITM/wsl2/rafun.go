package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

var (
	ifiFlag     = flag.String("i", "", "network interface to use for NDP communication (default: automatic)")
	addrFlag    = flag.String("a", string(ndp.LinkLocal), "address to use for NDP communication (unspecified, linklocal, uniquelocal, global, or a literal IPv6 address)")
	dnsAaddr    = flag.String("dnsAaddr", "192.0.2.1", "A dns response")
	dnsAAAAaddr = flag.String("dnsAAAAaddr", "2001:db8::1", "AAAA dns response")
	raPrefix    = flag.String("raPrefix", "2001:db8::", "Prefix to advertise in the router advertisements")
	raDNSaddr   = flag.String("raDNSaddr", "2001:db8::1", "Address to advertise as DNS server in the router advertisements")
	wpaddat     = flag.String("wpaddat", "", "The content of the wpad.dat file ('SOCKS ip')")
	ll          = log.New(os.Stderr, "rafun> ", 0)
)

func main() {
	flag.Parse()

	ifi, err := findInterface(*ifiFlag)
	if err != nil {
		ll.Fatalf("failed to get interface: %v", err)
	}

	addr := ndp.Addr(*addrFlag)
	c, ip, err := ndp.Dial(ifi, addr)
	if err != nil {
		ll.Fatalf("failed to dial NDP connection: %v", err)
	}
	defer c.Close()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Router Advertisements
	go func() {
		wg.Add(1)
		defer wg.Done()
		ll.Printf("RA interface: %s, link-layer address: %s, IPv6 address: %s, IPv6 DNS address: %s",
			ifi.Name, ifi.HardwareAddr, ip, *raDNSaddr)

		if err := doRA(ctx, c, ifi.HardwareAddr, ll); err != nil {
			// Context cancel means a signal was sent, so no need to log an error.
			if err != context.Canceled {
				ll.Fatalf("Router advertisement failed: %s\n", err.Error())
			}
		}
	}()

	// DNS server
	srvDNS := &dns.Server{Addr: ":53", Net: "udp"}
	srvDNS.Handler = &dnsHandler{}
	go func() {
		wg.Add(1)
		defer wg.Done()
		ll.Print("DNS A response: ", *dnsAaddr)
		ll.Print("DNS AAAA response: ", *dnsAAAAaddr)
		if err := srvDNS.ListenAndServe(); err != nil {
			ll.Fatalf("DNS server failed: %s\n", err.Error())
		}
	}()

	// HTTP server
	http.HandleFunc("/", httpHandleFunc)
	srvHTTP := &http.Server{Addr: ":80"}
	go func() {
		wg.Add(1)
		defer wg.Done()
		ll.Printf("WPAD config: '%s'\n", *wpaddat)
		if err := srvHTTP.ListenAndServe(); err != nil {
			ll.Fatalf("HTTP server failed: %s\n", err.Error())
		}
	}()

	<-sigC
	srvDNS.Shutdown()
	srvHTTP.Shutdown(nil)
	cancel()

	wg.Wait()
	ll.Print("Shutdown done")
}

func doRA(ctx context.Context, c *ndp.Conn, addr net.HardwareAddr, ll *log.Logger) error {
	// This tool is mostly meant for testing so hardcode a bunch of values.
	m := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		//ManagedConfiguration: ,
		//OtherConfiguration: ,
		RouterSelectionPreference: ndp.High,
		RouterLifetime:            1800 * time.Second,
		//ReachableTime: ,
		//RetransmitTimer: ,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      addr,
			},
			//ndp.NewMTU(1500),
			&ndp.PrefixInformation{
				PrefixLength:                   64,
				OnLink:                         true,
				AutonomousAddressConfiguration: true,
				ValidLifetime:                  1810 * time.Second,
				PreferredLifetime:              1800 * time.Second,
				Prefix:                         net.ParseIP(*raPrefix),
			},
			&ndp.RouteInformation{
				// :: - 7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
				Prefix:        net.ParseIP("::"),
				PrefixLength:  1,
				Preference:    ndp.High,
				RouteLifetime: 1800 * time.Second,
			},
			&ndp.RouteInformation{
				// 8000:: - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
				Prefix:        net.ParseIP("8000::"),
				PrefixLength:  1,
				Preference:    ndp.High,
				RouteLifetime: 1800 * time.Second,
			},
			/*
				&ndp.RouteInformation{
					// ::ffff:0.0.0.0 - ::ffff:127.255.255.255
					Prefix:        net.ParseIP("::ffff:0000:0000"),
					PrefixLength:  97,
					Preference:    ndp.High,
					RouteLifetime: 1800 * time.Second,
				},
				&ndp.RouteInformation{
					// ::ffff:128.0.0.0 - ::ffff:255.255.255.255
					Prefix:        net.ParseIP("::ffff:8000:0000"),
					PrefixLength:  97,
					Preference:    ndp.High,
					RouteLifetime: 1800 * time.Second,
				},
			*/
			&ndp.RecursiveDNSServer{
				Lifetime: 1800 * time.Second,
				Servers: []net.IP{
					net.ParseIP(*raDNSaddr),
					//net.ParseIP("2606:4700:4700::1111"),
					//net.ParseIP("2606:4700:4700::1001"),
				},
			},
			/*
				&ndp.RawOption{
					Type:   7,
					Length: 1,
					Value:  []byte{0, 0, 0, 0, 0, 0, 0, 10},
				},
			*/
		},
	}

	// Expect any router solicitation message.
	check := func(m ndp.Message) bool {
		_, ok := m.(*ndp.RouterSolicitation)
		return ok
	}

	// Trigger an RA whenever an RS is received.
	rsC := make(chan struct{})
	recv := func(ll *log.Logger, msg ndp.Message, from net.IP) {
		//printMessage(ll, m, from)
		rsC <- struct{}{}
	}

	// We are now a "router".
	if err := c.JoinGroup(net.IPv6linklocalallrouters); err != nil {
		return fmt.Errorf("failed to join multicast group: %v", err)
	}

	var eg errgroup.Group
	eg.Go(func() error {
		// Send messages until cancelation or error.
		for {
			if err := c.WriteTo(m, nil, net.IPv6linklocalallnodes); err != nil {
				return fmt.Errorf("failed to send router advertisement: %v", err)
			}

			select {
			case <-ctx.Done():
				return nil
			// Trigger RA at regular intervals or on demand.
			case <-time.After(10 * time.Second):
			case <-rsC:
			}
		}
	})

	if err := receiveLoop(ctx, c, ll, check, recv); err != nil {
		return fmt.Errorf("failed to receive router solicitations: %v", err)
	}

	return eg.Wait()
}

func receiveLoop(
	ctx context.Context,
	c *ndp.Conn,
	ll *log.Logger,
	check func(m ndp.Message) bool,
	recv func(ll *log.Logger, msg ndp.Message, from net.IP),
) error {
	var count int
	for {
		msg, from, err := receive(ctx, c, check)
		switch err {
		case context.Canceled:
			ll.Printf("received %d message(s)", count)
			return nil
		case errRetry:
			continue
		case nil:
			count++
			recv(ll, msg, from)
		default:
			return err
		}
	}
}

var errRetry = errors.New("retry")

func receive(ctx context.Context, c *ndp.Conn, check func(m ndp.Message) bool) (ndp.Message, net.IP, error) {
	if err := c.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, nil, fmt.Errorf("failed to set deadline: %v", err)
	}

	msg, _, from, err := c.ReadFrom()
	if err == nil {
		if check != nil && !check(msg) {
			// Read a message, but it isn't the one we want.  Keep trying.
			return nil, nil, errRetry
		}

		// Got a message that passed the check, if check was not nil.
		return msg, from, nil
	}

	// Was the context canceled already?
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// Was the error caused by a read timeout, and should the loop continue?
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return nil, nil, errRetry
	}

	return nil, nil, fmt.Errorf("failed to read message: %v", err)
}

func findInterface(name string) (*net.Interface, error) {
	if name != "" {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("could not find interface %q: %v", name, err)
		}

		return ifi, nil
	}

	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, ifi := range ifis {
		// Is the interface up and not a loopback?
		if ifi.Flags&net.FlagUp != 1 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Does the interface have an IPv6 address assigned?
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}

		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			// Is this address an IPv6 address?
			if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
				return &ifi, nil
			}
		}
	}

	return nil, errors.New("could not find a usable IPv6-enabled interface")
}

func httpHandleFunc(w http.ResponseWriter, r *http.Request) {
	ll.Printf("HTTP Request: %s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	switch r.URL.Path {
	case "/ncsi.txt":
		// http://www.msftncsi.com/ncsi.txt
		fmt.Fprintf(w, "Microsoft NCSI")
	case "/connecttest.txt":
		// http://www.msftconnecttest.com/connecttest.txt
		fmt.Fprintf(w, "Microsoft Connect Test")
	case "/success.txt":
		// http://detectportal.firefox.com/success.txt
		fmt.Fprintf(w, "success\n")
	case "/wpad.dat":
		if *wpaddat != "" {
			w.Header().Add("content-type", "application/x-ns-proxy-autoconfig")
			fmt.Fprintf(w, `function FindProxyForURL(url, host) { return "%s"; }`, *wpaddat)
		}
	default:
		fmt.Fprintf(w, "ok")
	}
}

type dnsHandler struct{}

func (*dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	//msg.Authoritative = true
	msg.RecursionAvailable = true
	for _, q := range r.Question {
		ll.Println("DNS Query: ", q.String())
		if strings.HasPrefix(q.Name, "wpad") && *wpaddat == "" {
			// do not respond to wpad requests if not configured
			continue
		}
		switch q.Qtype {
		case dns.TypeA:
			if q.Name == "ipv6.msftncsi.com" {
				// this domain doesn't have an A record
				continue
			}
			ip4 := *dnsAaddr
			if q.Name == "dns.msftncsi.com" {
				ip4 = "131.107.255.255"
			}
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip4),
			})
		case dns.TypeAAAA:
			ip6 := *dnsAAAAaddr
			if q.Name == "dns.msftncsi.com" {
				ip6 = "fd3e:4f5a:5b81::1"
			}
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(ip6),
			})
		}
	}
	w.WriteMsg(&msg)
}
