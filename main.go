// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

var listenAddr string
var targetAddr4 string
var targetAddr6 string
var allowedSubnetsPath string
var mark int
var verbose int
var listeners int

var allowedSubnets []*net.IPNet
var logger *zap.Logger

func init() {
	flag.StringVar(&listenAddr, "l", "0.0.0.0:8443", "Adress the proxy listens on")
	flag.StringVar(&targetAddr4, "4", "127.0.0.1:443", "Address to which IPv4 TCP traffic will be forwarded to")
	flag.StringVar(&targetAddr6, "6", "[::1]:443", "Address to which IPv6 TCP traffic will be forwarded to")
	flag.IntVar(&mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.StringVar(&allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occuring in individual connections
2 - log all state changes of individual connections`)
	flag.IntVar(&listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
}

func readRemoteAddrPROXYv2(conn net.Conn, ctrlBuf []byte) (net.Addr, net.Addr, []byte, error) {
	if (ctrlBuf[12] >> 4) != 2 {
		return nil, nil, nil, fmt.Errorf("unknown protocol version %d", ctrlBuf[12]>>4)
	}

	if ctrlBuf[12]&0xF > 1 {
		return nil, nil, nil, fmt.Errorf("unknown command %d", ctrlBuf[12]&0xF)
	}

	if ctrlBuf[12]&0xF == 1 && ctrlBuf[13] != 0x11 && ctrlBuf[13] != 0x21 {
		return nil, nil, nil, fmt.Errorf("invalid family/protocol %d/%d", ctrlBuf[13]>>4, ctrlBuf[13]&0xF)
	}

	var dataLen uint16
	reader := bytes.NewReader(ctrlBuf[14:16])
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode address data length: %s", err.Error())
	}

	if len(ctrlBuf) < 16+int(dataLen) {
		return nil, nil, nil, fmt.Errorf("incomplete PROXY header")
	}

	if ctrlBuf[12]&0xF == 0 { // LOCAL
		return conn.RemoteAddr(), conn.LocalAddr(), ctrlBuf[16+dataLen:], nil
	}

	var sport, dport uint16
	if ctrlBuf[13] == 0x11 { // IPv4
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		reader = bytes.NewReader(ctrlBuf[48:])
	}
	if err := binary.Read(reader, binary.BigEndian, &sport); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode source TCP port: %s", err.Error())
	}
	if err := binary.Read(reader, binary.BigEndian, &dport); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode destination TCP port: %s", err.Error())
	}

	if ctrlBuf[13] == 0x11 { // TCP over IPv4
		srcIP := net.IPv4(ctrlBuf[16], ctrlBuf[17], ctrlBuf[18], ctrlBuf[19])
		dstIP := net.IPv4(ctrlBuf[20], ctrlBuf[21], ctrlBuf[22], ctrlBuf[23])
		return &net.TCPAddr{IP: srcIP, Port: int(sport)},
			&net.TCPAddr{IP: dstIP, Port: int(dport)},
			ctrlBuf[16+dataLen:], nil
	}

	return &net.TCPAddr{IP: ctrlBuf[16:32], Port: int(sport)},
		&net.TCPAddr{IP: ctrlBuf[32:48], Port: int(dport)},
		ctrlBuf[16+dataLen:], nil
}

func readRemoteAddrPROXYv1(conn net.Conn, ctrlBuf []byte) (net.Addr, net.Addr, []byte, error) {
	str := string(ctrlBuf)
	if idx := strings.Index(str, "\r\n"); idx >= 0 {
		var protocol, src, dst string
		var sport, dport int
		n, err := fmt.Sscanf(str, "PROXY %s", &protocol)
		if err != nil {
			return nil, nil, nil, err
		}
		if n != 1 {
			return nil, nil, nil, fmt.Errorf("failed to decode elements")
		}
		if protocol == "UNKNOWN" {
			return conn.RemoteAddr(), conn.LocalAddr(), ctrlBuf[idx+2:], nil
		}
		if protocol != "TCP4" && protocol != "TCP6" {
			return nil, nil, nil, fmt.Errorf("unknown protocol %s", protocol)
		}

		n, err = fmt.Sscanf(str, "PROXY %s %s %s %d %d", &protocol, &src, &dst, &sport, &dport)
		if err != nil {
			return nil, nil, nil, err
		}
		if n != 5 {
			return nil, nil, nil, fmt.Errorf("failed to decode elements")
		}
		srcIP := net.ParseIP(src)
		if srcIP == nil {
			return nil, nil, nil, fmt.Errorf("failed to parse source IP address %s", src)
		}
		dstIP := net.ParseIP(dst)
		if dstIP == nil {
			return nil, nil, nil, fmt.Errorf("failed to parse destination IP address %s", dst)
		}
		return &net.TCPAddr{IP: srcIP, Port: sport},
			&net.TCPAddr{IP: dstIP, Port: dport},
			ctrlBuf[idx+2:], nil
	}

	return nil, nil, nil, fmt.Errorf("did not find \\r\\n in first data segment")
}

func readRemoteAddr(conn net.Conn) (net.Addr, net.Addr, []byte, error) {
	buf := make([]byte, 108)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read header: %s", err.Error())
	}

	if n >= 16 && bytes.Equal(buf[:12],
		[]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}) {
		saddr, daddr, rest, err := readRemoteAddrPROXYv2(conn, buf[:n])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse PROXY v2 header: %s", err.Error())
		}
		return saddr, daddr, rest, err
	}

	if n >= 8 && bytes.Equal(buf[:5], []byte("PROXY")) {
		saddr, daddr, rest, err := readRemoteAddrPROXYv1(conn, buf[:n])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse PROXY v1 header: %s", err.Error())
		}
		return saddr, daddr, rest, err
	}

	return nil, nil, nil, fmt.Errorf("PROXY header missing")
}

func dialUpstreamControl(sport int, connLog *zap.Logger) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCTNT, 2): %s", syscallErr.Error())
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1): %s", syscallErr.Error())
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, SO_REUSEADDR, 1): %s", syscallErr.Error())
				return
			}

			if sport == 0 {
				ipBindAddressNoPort := 24
				err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
				if err != nil && verbose > 1 {
					connLog.Debug("Failed to set IP_BIND_ADDRESS_NO_PORT", zap.Error(err))
				}
			}

			if mark != 0 {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %s", mark, syscallErr.Error())
					return
				}
			}

			if network == "tcp6" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IPV6_V6ONLY, 0)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IPV6_ONLY, 0): %s", syscallErr.Error())
					return
				}
			}
		})

		if err != nil {
			return err
		}
		return syscallErr
	}
}

func copyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

func checkOriginAllowed(conn net.Conn) bool {
	if len(allowedSubnets) == 0 {
		return true
	}

	addr := conn.RemoteAddr().(*net.TCPAddr)
	for _, ipNet := range allowedSubnets {
		if ipNet.Contains(addr.IP) {
			return true
		}
	}
	return false
}

func handleConnection(conn net.Conn, listenLog *zap.Logger) {
	defer conn.Close()
	connLog := listenLog.With(zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("localAddr", conn.LocalAddr().String()))

	if !checkOriginAllowed(conn) {
		connLog.Debug("connection origin not in allowed subnets", zap.Bool("dropConnection", true))
		return
	}

	if verbose > 1 {
		connLog.Debug("new connection")
	}

	saddr, _, restBytes, err := readRemoteAddr(conn)
	if err != nil {
		connLog.Debug("failed to parse PROXY header", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}

	targetAddr := targetAddr6
	if strings.ContainsRune(saddr.String(), '.') { // poor man's ipv6 check - golang makes it unnecessarily hard
		targetAddr = targetAddr4
	}

	connLog = connLog.With(zap.String("clientAddr", saddr.String()), zap.String("targetAddr", targetAddr))
	if verbose > 1 {
		connLog.Debug("successfuly parsed PROXY header")
	}

	dialer := net.Dialer{LocalAddr: saddr, Control: dialUpstreamControl(saddr.(*net.TCPAddr).Port, connLog)}
	upstreamConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		connLog.Debug("failed to establish upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if verbose > 1 {
		connLog.Debug("successfuly established upstream connection")
	}

	if err := conn.(*net.TCPConn).SetNoDelay(true); err != nil {
		connLog.Debug("failed to set nodelay on downstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if verbose > 1 {
		connLog.Debug("successfuly set NoDelay on downstream connection")
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		connLog.Debug("failed to set nodelay on upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if verbose > 1 {
		connLog.Debug("successfuly set NoDelay on upstream connection")
	}

	for len(restBytes) > 0 {
		n, err := upstreamConn.Write(restBytes)
		if err != nil {
			connLog.Debug("failed to write data to upstream connection",
				zap.Error(err), zap.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	outErr := make(chan error, 2)
	go copyData(upstreamConn, conn, outErr)
	go copyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		connLog.Debug("connection broken", zap.Error(err), zap.Bool("dropConnection", true))
	} else if verbose > 1 {
		connLog.Debug("connection closing")
	}
}

func listen(listenerNum int, errors chan<- error) {
	listenLog := logger.With(zap.Int("listenerNum", listenerNum))

	listenConfig := net.ListenConfig{}
	if listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					listenLog.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	ctx := context.Background()
	ln, err := listenConfig.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		listenLog.Error("failed to bind listener", zap.String("listenAddr", listenAddr), zap.Error(err))
		errors <- err
		return
	}

	listenLog.Info("listening", zap.String("listenAddr", listenAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			listenLog.Error("failed to accept new connection", zap.Error(err))
			errors <- err
			return
		}

		go handleConnection(conn, listenLog)
	}
}

func loadAllowedSubnets() error {
	file, err := os.Open(allowedSubnetsPath)
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
		allowedSubnets = append(allowedSubnets, ipNet)
		logger.Info("allowed subnet", zap.String("subnet", ipNet.String()))
	}

	return nil
}

func initLogger() error {
	logConfig := zap.NewProductionConfig()
	if verbose > 0 {
		logConfig.Level.SetLevel(zap.DebugLevel)
	}

	l, err := logConfig.Build()
	if err == nil {
		logger = l
	}
	return err
}

func main() {
	flag.Parse()
	if err := initLogger(); err != nil {
		log.Fatalf("Failed to initialize logging: %s", err.Error())
	}
	defer logger.Sync()

	if listeners <= 0 {
		logger.Fatal("--listeners has to be >= 1")
	}

	if allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			logger.Fatal("failed to load allowed subnets file", zap.String("path", allowedSubnetsPath), zap.Error(err))
		}
	}

	listenErrors := make(chan error, listeners)
	for i := 0; i < listeners; i++ {
		go listen(i, listenErrors)
	}
	for i := 0; i < listeners; i++ {
		<-listenErrors
	}
}
