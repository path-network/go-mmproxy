// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

type options struct {
	Protocol           string
	ListenAddr         string
	TargetAddr4        string
	TargetAddr6        string
	Mark               int
	Verbose            int
	allowedSubnetsPath string
	AllowedSubnets     []*net.IPNet
	Listeners          int
	Logger             *slog.Logger
	udpCloseAfter      int
	UDPCloseAfter      time.Duration
}

var Opts options

func init() {
	flag.StringVar(&Opts.Protocol, "p", "tcp", "Protocol that will be proxied: tcp, udp")
	flag.StringVar(&Opts.ListenAddr, "l", "0.0.0.0:8443", "Address the proxy listens on")
	flag.StringVar(&Opts.TargetAddr4, "4", "127.0.0.1:443", "Address to which IPv4 traffic will be forwarded to")
	flag.StringVar(&Opts.TargetAddr6, "6", "[::1]:443", "Address to which IPv6 traffic will be forwarded to")
	flag.IntVar(&Opts.Mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.IntVar(&Opts.Verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&Opts.allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&Opts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&Opts.udpCloseAfter, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up")
}

func listen(listenerNum int, errors chan<- error) {
	logger := Opts.Logger.With(slog.Int("listenerNum", listenerNum),
		slog.String("protocol", Opts.Protocol), slog.String("listenAdr", Opts.ListenAddr))

	listenConfig := net.ListenConfig{}
	if Opts.Listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	if Opts.Protocol == "tcp" {
		tcpListen(&listenConfig, logger, errors)
	} else {
		udpListen(&listenConfig, logger, errors)
	}
}

func loadAllowedSubnets() error {
	file, err := os.Open(Opts.allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return err
		}
		Opts.AllowedSubnets = append(Opts.AllowedSubnets, ipNet)
		Opts.Logger.Info("allowed subnet", slog.String("subnet", ipNet.String()))
	}

	return nil
}

func main() {
	flag.Parse()
	lvl := slog.LevelInfo
	if Opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}
	Opts.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	if Opts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			Opts.Logger.Error("failed to load allowed subnets file", "path", Opts.allowedSubnetsPath, "error", err)
		}
	}

	if Opts.Protocol != "tcp" && Opts.Protocol != "udp" {
		Opts.Logger.Error("--protocol has to be one of udp, tcp", slog.String("protocol", Opts.Protocol))
		os.Exit(1)
	}

	if Opts.Mark < 0 {
		Opts.Logger.Error("--mark has to be >= 0", slog.Int("mark", Opts.Mark))
		os.Exit(1)
	}

	if Opts.Verbose < 0 {
		Opts.Logger.Error("-v has to be >= 0", slog.Int("verbose", Opts.Verbose))
		os.Exit(1)
	}

	if Opts.Listeners < 1 {
		Opts.Logger.Error("--listeners has to be >= 1")
		os.Exit(1)
	}

	if _, err := netip.ParseAddr(Opts.ListenAddr); err != nil {
		Opts.Logger.Error("listen address is malformed", "error", err)
		os.Exit(1)
	}

	if _, err := netip.ParseAddr(Opts.TargetAddr4); err != nil {
		Opts.Logger.Error("ipv4 target address is malformed", "error", err)
		os.Exit(1)
	}

	if _, err := netip.ParseAddr(Opts.TargetAddr6); err != nil {
		Opts.Logger.Error("ipv6 target address is malformed", "error", err)
		os.Exit(1)
	}

	if Opts.udpCloseAfter < 0 {
		Opts.Logger.Error("--close-after has to be >= 0", slog.Int("close-after", Opts.udpCloseAfter))
		os.Exit(1)
	}
	Opts.UDPCloseAfter = time.Duration(Opts.udpCloseAfter) * time.Second

	listenErrors := make(chan error, Opts.Listeners)
	for i := 0; i < Opts.Listeners; i++ {
		go listen(i, listenErrors)
	}
	for i := 0; i < Opts.Listeners; i++ {
		<-listenErrors
	}
}
