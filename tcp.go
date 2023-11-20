// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
)

func tcpCopyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

func tcpHandleConnection(conn net.Conn, logger *slog.Logger) {
	defer conn.Close()
	logger = logger.With(slog.String("remoteAddr", conn.RemoteAddr().String()),
		slog.String("localAddr", conn.LocalAddr().String()))

	if !checkOriginAllowed(conn.RemoteAddr().(*net.TCPAddr).IP) {
		logger.Debug("connection origin not in allowed subnets", slog.Bool("dropConnection", true))
		return
	}

	if Opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	buffer := GetBuffer()
	defer func() {
		if buffer != nil {
			PutBuffer(buffer)
		}
	}()

	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug("failed to read PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	saddr, _, restBytes, err := proxyReadRemoteAddr(buffer[:n], TCP)
	if err != nil {
		logger.Debug("failed to parse PROXY header", "error", err, slog.Bool("dropConnection", true))
		return
	}

	targetAddr := Opts.TargetAddr6
	if saddr == nil {
		if netip.MustParseAddrPort(conn.RemoteAddr().String()).Addr().Is4() {
			targetAddr = Opts.TargetAddr4
		}
	} else if netip.MustParseAddrPort(saddr.String()).Addr().Is4() {
		targetAddr = Opts.TargetAddr4
	}

	clientAddr := "UNKNOWN"
	if saddr != nil {
		clientAddr = saddr.String()
	}
	logger = logger.With(slog.String("clientAddr", clientAddr), slog.String("targetAddr", targetAddr.String()))
	if Opts.Verbose > 1 {
		logger.Debug("successfully parsed PROXY header")
	}

	dialer := net.Dialer{LocalAddr: saddr}
	if saddr != nil {
		dialer.Control = dialUpstreamControl(saddr.(*net.TCPAddr).Port)
	}
	upstreamConn, err := dialer.Dial("tcp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to establish upstream connection", "error", err, slog.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if Opts.Verbose > 1 {
		logger.Debug("successfully established upstream connection")
	}

	if err := conn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on downstream connection", "error", err, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on downstream connection")
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on upstream connection", "error", err, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on upstream connection")
	}

	for len(restBytes) > 0 {
		n, err := upstreamConn.Write(restBytes)
		if err != nil {
			logger.Debug("failed to write data to upstream connection",
				"error", err, slog.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	PutBuffer(buffer)
	buffer = nil

	outErr := make(chan error, 2)
	go tcpCopyData(upstreamConn, conn, outErr)
	go tcpCopyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		logger.Debug("connection broken", "error", err, slog.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("connection closing")
	}
}

func tcpListen(listenConfig *net.ListenConfig, logger *slog.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.Listen(ctx, "tcp", Opts.ListenAddr.String())
	if err != nil {
		logger.Error("failed to bind listener", "error", err)
		errors <- err
		return
	}

	logger.Info("listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("failed to accept new connection", "error", err)
			errors <- err
			return
		}

		go tcpHandleConnection(conn, logger)
	}
}
