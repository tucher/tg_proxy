package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
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

func main() {

	filter := createFilter(
		[]string{
			"149.154.160.0/22",
			"149.154.164.0/22",
			"149.154.168.0/22",
			"149.154.175.0/22",
			"91.108.4.0/22",
			"91.108.8.0/22",
			"91.108.12.0/22",
			"91.108.16.0/22",
			"91.108.56.0/22",
		},
		[]string{
			"web.telegram.org",
			"telegram.org",
			"t.me",
			"telegram.me",
			"desktop.telegram.org",
			"telegram.dog",
			"venus.web.telegram.org",
			"pluto-1.web.telegram.org",
		},
	)
	fmt.Printf("Allowed hosts:\n%+v\nAllowed networks:\n%+v\n", filter.hosts, filter.networks)

	server, _ := socks5.New(&socks5.Config{
		ConnLimit:      20000,
		Rules:          filter,
		IdleTimeout:    time.Minute * 2,
		ConnectTimeout: time.Second * 5,
		Credentials:    socks5.StaticCredentials(map[string]string{"123abc": "abc123"}),
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
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6666", nil)
	server.ListenAndServe("tcp", []string{"0.0.0.0:443"})
}
