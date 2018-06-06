package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tucher/go-socks5"
)

type tgFilter struct {
	networks []*net.IPNet
	hosts    []string
}

func (p *tgFilter) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if req.Command != socks5.ConnectCommand {
		return ctx, false
	}

	for _, h := range p.hosts {
		if req.DestAddr.FQDN == h {
			return ctx, true
		}
	}

	for _, n := range p.networks {
		if n.Contains(req.DestAddr.IP) {
			return ctx, true
		}
	}

	return ctx, false
}

func createFilter(networks []string, hosts []string) *tgFilter {
	filter := &tgFilter{hosts: hosts}
	for _, n := range networks {
		if _, newNet, err := net.ParseCIDR(n); err == nil {
			filter.networks = append(filter.networks, newNet)
		}
	}
	return filter
}

var (
	connCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_connections_count",
		Help: "Counter of current opened tcp connections",
	})
	connectionDurations = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "connection_duration_seconds",
			Help:    "Connection duration",
			Buckets: prometheus.ExponentialBuckets(0.02, 3, 15),
		},
	)
)

type TrapNoAuthAuthenticator struct {
}

func (a TrapNoAuthAuthenticator) GetCode() uint8 {
	return socks5.NoAuth
}

func (a TrapNoAuthAuthenticator) Authenticate(reader io.Reader, writer net.Conn) (*socks5.AuthContext, error) {
	writer.Write([]byte{uint8(5), socks5.NoAuth})

	var destIPAddress net.IP
	var FQDN string
	var Port int

	srcHost, srcPort, _ := net.SplitHostPort(writer.RemoteAddr().String())

	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(reader, header, 3); err == nil {
		if header[0] == 5 {

			addrType := []byte{0}
			if _, err := reader.Read(addrType); err == nil {
				switch addrType[0] {
				case 1:
					addr := make([]byte, 4)
					if _, err := io.ReadAtLeast(reader, addr, len(addr)); err == nil {
						destIPAddress = net.IP(addr)
					}
				case 4:
					addr := make([]byte, 16)
					if _, err := io.ReadAtLeast(reader, addr, len(addr)); err == nil {
						destIPAddress = net.IP(addr)
					}
				case 3:
					if _, err := reader.Read(addrType); err == nil {
						addrLen := int(addrType[0])
						fqdn := make([]byte, addrLen)
						if _, err := io.ReadAtLeast(reader, fqdn, addrLen); err == nil {
							FQDN = string(fqdn)
						}
					}
				}
				// Read the port
				port := []byte{0, 0}
				if _, err := io.ReadAtLeast(reader, port, 2); err != nil {
					return nil, err
				}
				Port = (int(port[0]) << 8) | int(port[1])
			}
		}
	}

	if f, err := os.OpenFile("suspicious_auth_attempts.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		f.WriteString(fmt.Sprintf("%v,%v,%v,%v,%v,%v\n",
			time.Now().Format("2006-01-02 15:04:05.000"),
			srcHost,
			srcPort,
			FQDN,
			destIPAddress,
			Port))
		f.Close()
	}

	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16

	addrType = 1
	addrBody = []byte{0, 0, 0, 0}
	addrPort = 0

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = 5
	msg[1] = 1
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	writer.Write(msg)

	return nil, socks5.UserAuthFailed
}

func main() {

	// filter := createFilter(
	// 	[]string{
	// 		"149.154.160.0/22",
	// 		"149.154.164.0/22",
	// 		"149.154.168.0/22",
	// 		"149.154.175.0/22",
	// 		"91.108.4.0/22",
	// 		"91.108.8.0/22",
	// 		"91.108.12.0/22",
	// 		"91.108.16.0/22",
	// 		"91.108.56.0/22",
	// 	},
	// 	[]string{
	// 		"web.telegram.org",
	// 		"telegram.org",
	// 		"t.me",
	// 		"telegram.me",
	// 		"desktop.telegram.org",
	// 		"telegram.dog",
	// 		"venus.web.telegram.org",
	// 		"pluto-1.web.telegram.org",
	// 	},
	// )
	// fmt.Printf("Allowed hosts:\n%+v\nAllowed networks:\n%+v\n", filter.hosts, filter.networks)

	server, _ := socks5.New(&socks5.Config{
		ConnLimit: 20000,
		// Rules:          filter,
		IdleTimeout:    time.Minute * 2,
		ConnectTimeout: time.Second * 5,
		AuthMethods: []socks5.Authenticator{
			&socks5.UserPassAuthenticator{socks5.StaticCredentials(map[string]string{"123abc": "abc123"})},
			&TrapNoAuthAuthenticator{},
		},
	})

	prometheus.MustRegister(connCountGauge, connectionDurations)
	go func() {
		for newCount := range server.GetConnCountChan() {
			connCountGauge.Set(float64(newCount))
		}
	}()
	go func() {
		for finishedConnInfo := range server.GetFinishedConnChan() {
			connectionDurations.Observe(finishedConnInfo.Duration.Seconds())
		}
	}()
	go func() {

		for authFailedInfo := range server.GetAuthFailedInfoChan() {
			if len(authFailedInfo.Reason) == 1 && authFailedInfo.Reason[0] == 0 {

			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6666", nil)
	server.ListenAndServe("tcp", []string{"0.0.0.0:443"})
}
