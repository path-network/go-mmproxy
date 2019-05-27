// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
)

var listenAddr string
var targetAddr4 string
var targetAddr6 string
var mark int

func init() {
	flag.StringVar(&listenAddr, "l", "0.0.0.0:8443", "Adress the proxy listens on")
	flag.StringVar(&targetAddr4, "4", "0.0.0.0:443", "Address to which IPv4 TCP traffic will be forwarded to")
	flag.StringVar(&targetAddr6, "6", "[::]:443", "Address to which IPv6 TCP traffic will be forwarded to")
	flag.IntVar(&mark, "mark", 123, "The mark that will be set on outbound packets")
}

func readRemoteAddrPROXYv2(conn net.Conn, ctrlBuf []byte) (net.Addr, net.Addr, []byte, error) {
	if (ctrlBuf[12] >> 4) != 2 {
		return nil, nil, nil, fmt.Errorf("unknown protocol version %d", ctrlBuf[12]>>4)
	}

	if ctrlBuf[12]&0xFF > 1 {
		return nil, nil, nil, fmt.Errorf("unknown command %d", ctrlBuf[12]&0xFF)
	}

	if ctrlBuf[12]&0xFF == 1 && ctrlBuf[13] != 0x11 && ctrlBuf[13] != 0x21 {
		return nil, nil, nil, fmt.Errorf("invalid family/protocol %d/%d", ctrlBuf[13]>>4, ctrlBuf[13]&0xFF)
	}

	var dataLen uint16
	reader := bytes.NewReader(ctrlBuf[14:16])
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode address data length: %s", err.Error())
	}

	if ctrlBuf[12]&0xFF == 1 { // LOCAL
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
		return &net.TCPAddr{IP: srcIP, Port: int(sport)}, &net.TCPAddr{IP: dstIP, Port: int(dport)}, ctrlBuf[16+dataLen:], nil
	}

	return &net.TCPAddr{IP: ctrlBuf[16:32], Port: int(sport)}, &net.TCPAddr{IP: ctrlBuf[32:48], Port: int(dport)}, ctrlBuf[16+dataLen:], nil
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
		return &net.TCPAddr{IP: srcIP, Port: sport}, &net.TCPAddr{IP: dstIP, Port: dport}, ctrlBuf[idx+2:], nil
	}

	return nil, nil, nil, fmt.Errorf("did not find \\r\\n in first data segment")
}

func readRemoteAddr(conn net.Conn) (net.Addr, net.Addr, []byte, error) {
	buf := make([]byte, 108)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read header: %s", err.Error())
	}

	if n >= 16 && bytes.Equal(buf[:13], []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}) {
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

func dialUpstreamControl(sport int) func(string, string, syscall.RawConn) error {
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
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %s", mark, syscallErr.Error())
				return
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

func handleConnection(conn net.Conn) {
	defer conn.Close()

	saddr, _, restBytes, err := readRemoteAddr(conn)
	if err != nil {
		log.Printf("Failed to parse PROXY data from %s: %s", conn.RemoteAddr().String(), err.Error())
		return
	}

	targetAddr := targetAddr6
	if strings.ContainsRune(saddr.String(), '.') { // poor man's ipv6 check - golang makes it unnecessarily hard
		targetAddr = targetAddr4
	}

	dialer := net.Dialer{LocalAddr: saddr, Control: dialUpstreamControl(saddr.(*net.TCPAddr).Port)}
	upstreamConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to establish upstream connection %s -> %s (PROXY %s -> %s): %s",
			conn.RemoteAddr().String(), conn.LocalAddr().String(), saddr.String(), targetAddr, err.Error())
		return
	}

	if err := conn.(*net.TCPConn).SetNoDelay(true); err != nil {
		log.Printf("Failed to set nodelay on upstream connection %s -> %s (PROXY %s -> %s): %s",
			conn.RemoteAddr().String(), conn.LocalAddr().String(), saddr.String(), targetAddr, err.Error())
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		log.Printf("Failed to set nodelay on upstream connection %s -> %s (PROXY %s -> %s): %s",
			conn.RemoteAddr().String(), conn.LocalAddr().String(), saddr.String(), targetAddr, err.Error())
	}

	defer upstreamConn.Close()

	for len(restBytes) > 0 {
		n, err := conn.Write(restBytes)
		if err != nil {
			log.Printf("Failed to write data to upstream connection %s -> %s (PROXY %s -> %s): %s",
				conn.RemoteAddr().String(), conn.LocalAddr().String(), saddr.String(), targetAddr, err.Error())
			return
		}
		restBytes = restBytes[n:]
	}

	outErr := make(chan error, 2)
	go copyData(upstreamConn, conn, outErr)
	go copyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		log.Printf("Connection %s -> %s (PROXY %s -> %s): %s",
			conn.RemoteAddr().String(), conn.LocalAddr().String(), saddr.String(), targetAddr, err.Error())
	}
}

func main() {
	flag.Parse()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to bind to %s: %s\n", listenAddr, err.Error())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Failed to accept new connection: %s\n", err.Error())
		}

		go handleConnection(conn)
	}
}
