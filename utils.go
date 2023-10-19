// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"syscall"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

func CheckOriginAllowed(remoteIP net.IP) bool {
	if len(Opts.AllowedSubnets) == 0 {
		return true
	}

	for _, ipNet := range Opts.AllowedSubnets {
		if ipNet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func DialUpstreamControl(sport int) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			if Opts.Protocol == "tcp" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCTNT, 2): %w", syscallErr)
					return
				}
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1): %w", syscallErr)
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, SO_REUSEADDR, 1): %w", syscallErr)
				return
			}

			if sport == 0 {
				ipBindAddressNoPort := 24
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, IPPROTO_IP, %d): %w", Opts.Mark, syscallErr)
					return
				}
			}

			if Opts.Mark != 0 {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Opts.Mark)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %w", Opts.Mark, syscallErr)
					return
				}
			}

			if network == "tcp6" || network == "udp6" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IPV6_ONLY, 0): %w", syscallErr)
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
