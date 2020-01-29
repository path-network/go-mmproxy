// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"go.uber.org/zap"
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
	Logger             *zap.Logger
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
	logger := Opts.Logger.With(zap.Int("listenerNum", listenerNum),
		zap.String("protocol", Opts.Protocol), zap.String("listenAdr", Opts.ListenAddr))

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
		TCPListen(&listenConfig, logger, errors)
	} else {
		UDPListen(&listenConfig, logger, errors)
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
		Opts.Logger.Info("allowed subnet", zap.String("subnet", ipNet.String()))
	}

	return nil
}

func initLogger() error {
	logConfig := zap.NewProductionConfig()
	if Opts.Verbose > 0 {
		logConfig.Level.SetLevel(zap.DebugLevel)
	}

	l, err := logConfig.Build()
	if err == nil {
		Opts.Logger = l
	}
	return err
}

func main() {
	flag.Parse()
	if err := initLogger(); err != nil {
		log.Fatalf("Failed to initialize logging: %s", err.Error())
	}
	defer Opts.Logger.Sync()

	if Opts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			Opts.Logger.Fatal("failed to load allowed subnets file",
				zap.String("path", Opts.allowedSubnetsPath), zap.Error(err))
		}
	}

	if Opts.Protocol != "tcp" && Opts.Protocol != "udp" {
		Opts.Logger.Fatal("--protocol has to be one of udp, tcp", zap.String("protocol", Opts.Protocol))
	}

	if Opts.Mark < 0 {
		Opts.Logger.Fatal("--mark has to be >= 0", zap.Int("mark", Opts.Mark))
	}

	if Opts.Verbose < 0 {
		Opts.Logger.Fatal("-v has to be >= 0", zap.Int("verbose", Opts.Verbose))
	}

	if Opts.Listeners < 1 {
		Opts.Logger.Fatal("--listeners has to be >= 1")
	}

	if Opts.udpCloseAfter < 0 {
		Opts.Logger.Fatal("--close-after has to be >= 0", zap.Int("close-after", Opts.udpCloseAfter))
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
