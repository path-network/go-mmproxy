// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func readRemoteAddrPROXYv2(ctrlBuf []byte, protocol Protocol) (net.Addr, net.Addr, []byte, error) {
	if (ctrlBuf[12] >> 4) != 2 {
		return nil, nil, nil, fmt.Errorf("unknown protocol version %d", ctrlBuf[12]>>4)
	}

	if ctrlBuf[12]&0xF > 1 {
		return nil, nil, nil, fmt.Errorf("unknown command %d", ctrlBuf[12]&0xF)
	}

	if ctrlBuf[12]&0xF == 1 && ((protocol == TCP && ctrlBuf[13] != 0x11 && ctrlBuf[13] != 0x21) ||
		(protocol == UDP && ctrlBuf[13] != 0x12 && ctrlBuf[13] != 0x22)) {
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
		return nil, nil, ctrlBuf[16+dataLen:], nil
	}

	var sport, dport uint16
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		reader = bytes.NewReader(ctrlBuf[24:])
	} else {
		reader = bytes.NewReader(ctrlBuf[48:])
	}
	if err := binary.Read(reader, binary.BigEndian, &sport); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode source port: %s", err.Error())
	}
	if err := binary.Read(reader, binary.BigEndian, &dport); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode destination port: %s", err.Error())
	}

	var srcIP, dstIP net.IP
	if ctrlBuf[13]>>4 == 0x1 { // IPv4
		srcIP = net.IPv4(ctrlBuf[16], ctrlBuf[17], ctrlBuf[18], ctrlBuf[19])
		dstIP = net.IPv4(ctrlBuf[20], ctrlBuf[21], ctrlBuf[22], ctrlBuf[23])
	} else {
		srcIP = ctrlBuf[16:32]
		dstIP = ctrlBuf[32:48]
	}

	if ctrlBuf[13]&0xF == 0x1 { // TCP
		return &net.TCPAddr{IP: srcIP, Port: int(sport)},
			&net.TCPAddr{IP: dstIP, Port: int(dport)},
			ctrlBuf[16+dataLen:], nil
	}

	return &net.UDPAddr{IP: srcIP, Port: int(sport)},
		&net.UDPAddr{IP: dstIP, Port: int(dport)},
		ctrlBuf[16+dataLen:], nil
}

func readRemoteAddrPROXYv1(ctrlBuf []byte) (net.Addr, net.Addr, []byte, error) {
	str := string(ctrlBuf)
	if idx := strings.Index(str, "\r\n"); idx >= 0 {
		var headerProtocol, src, dst string
		var sport, dport int
		n, err := fmt.Sscanf(str, "PROXY %s", &headerProtocol)
		if err != nil {
			return nil, nil, nil, err
		}
		if n != 1 {
			return nil, nil, nil, fmt.Errorf("failed to decode elements")
		}
		if headerProtocol == "UNKNOWN" {
			return nil, nil, ctrlBuf[idx+2:], nil
		}
		if headerProtocol != "TCP4" && headerProtocol != "TCP6" {
			return nil, nil, nil, fmt.Errorf("unknown protocol %s", headerProtocol)
		}

		n, err = fmt.Sscanf(str, "PROXY %s %s %s %d %d", &headerProtocol, &src, &dst, &sport, &dport)
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

func PROXYReadRemoteAddr(buf []byte, protocol Protocol) (net.Addr, net.Addr, []byte, error) {
	if len(buf) >= 16 && bytes.Equal(buf[:12],
		[]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}) {
		saddr, daddr, rest, err := readRemoteAddrPROXYv2(buf, protocol)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse PROXY v2 header: %s", err.Error())
		}
		return saddr, daddr, rest, err
	}

	// PROXYv1 only works with TCP
	if protocol == TCP && len(buf) >= 8 && bytes.Equal(buf[:5], []byte("PROXY")) {
		saddr, daddr, rest, err := readRemoteAddrPROXYv1(buf)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse PROXY v1 header: %s", err.Error())
		}
		return saddr, daddr, rest, err
	}

	return nil, nil, nil, fmt.Errorf("PROXY header missing")
}
