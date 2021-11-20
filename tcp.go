// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"io"
	"net"

	"github.com/juju/ratelimit"
	"go.uber.org/zap"
)

func tcpCopyData(dst net.Conn, src net.Conn, ch chan<- error) {
	_, err := io.Copy(dst, src)
	ch <- err
}

type SpeedCtrl struct {
	net.Conn

	rbucket   *ratelimit.Bucket
	wbucket   *ratelimit.Bucket
}

func (c *SpeedCtrl) Read(data []byte) (n int, err error)  {
	n, err = c.Conn.Read(data)
	if n <= 0 {
		return n, err
	}
	if c.rbucket != nil {
		c.rbucket.Wait(int64(n))
	}
	return n, err
}

func (c *SpeedCtrl) Write(data []byte) (n int, err error) {
	if c.wbucket != nil {
		c.wbucket.Wait(int64(len(data)))
	}
	return c.Conn.Write(data)
}

func (c *SpeedCtrl) GetTCPConn() (*net.TCPConn, bool) {
	conn, ok := c.Conn.(*net.TCPConn)
	return conn, ok
}

func NewSpeedCtrl(conn net.Conn, rx int, rxBurst int, tx int, txBurst int) net.Conn {
	c := &SpeedCtrl{}
	c.Conn = conn
	if rx > 0 {
		if rxBurst < 0 {
			rxBurst = 0
		}
		c.rbucket = ratelimit.NewBucketWithRate(float64(rx), int64(rxBurst))
	}
	if tx > 0 {
		if txBurst < 0 {
			txBurst = 0
		}
		c.wbucket = ratelimit.NewBucketWithRate(float64(tx), int64(txBurst))
	}
	return c
}

type AddrFn func(conn net.Conn, logger *zap.Logger) (net.Addr, net.Addr, []byte, error)

func getProxyAddr(conn net.Conn, logger *zap.Logger) (net.Addr, net.Addr, []byte, error) {
	buffer := GetBuffer()
	defer PutBuffer(buffer)

	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug("failed to read PROXY header", zap.Error(err), zap.Bool("dropConnection", true))
		return nil, nil, nil, err
	}

	saddr, daddr, restBytes, err := PROXYReadRemoteAddr(buffer[:n], TCP)
	if err != nil {
		logger.Debug("failed to parse PROXY header", zap.Error(err), zap.Bool("dropConnection", true))
		return nil, nil, nil, err
	}

	return saddr, daddr, restBytes, err
}

func getRawAddr(conn net.Conn, logger *zap.Logger) (net.Addr, net.Addr, []byte, error) {
	saddr := conn.RemoteAddr()
	daddr := conn.LocalAddr()
	return saddr, daddr, nil, nil
}

func tcpHandleConnection(conn net.Conn, logger *zap.Logger, getAddr AddrFn) {
	defer conn.Close()
	logger = logger.With(zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("localAddr", conn.LocalAddr().String()))

	if !CheckOriginAllowed(conn.RemoteAddr().(*net.TCPAddr).IP) {
		logger.Debug("connection origin not in allowed subnets", zap.Bool("dropConnection", true))
		return
	}

	if Opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	saddr, _, restBytes, err := getAddr(conn, logger)
	if err != nil {
		logger.Debug("failed to get source address", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}
	targetAddr := Opts.TargetAddr6
	if saddr == nil {
		if AddrVersion(conn.RemoteAddr()) == 4 {
			targetAddr = Opts.TargetAddr4
		}
	} else if AddrVersion(saddr) == 4 {
		targetAddr = Opts.TargetAddr4
	}

	clientAddr := "UNKNOWN"
	if saddr != nil {
		clientAddr = saddr.String()
	}
	logger = logger.With(zap.String("clientAddr", clientAddr), zap.String("targetAddr", targetAddr))
	if Opts.Verbose > 1 {
		logger.Debug("successfully parsed get source address")
	}

	dialer := net.Dialer{LocalAddr: saddr}
	if saddr != nil {
		dialer.Control = DialUpstreamControl(saddr.(*net.TCPAddr).Port)
	}
	upstreamConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		logger.Debug("failed to establish upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
		return
	}

	defer upstreamConn.Close()
	if Opts.Verbose > 1 {
		logger.Debug("successfully established upstream connection")
	}

	var tcpConn *net.TCPConn
	switch v := conn.(type) {
	case *net.TCPConn:
		tcpConn = v
	case *SpeedCtrl:
		tcpConn, _ = v.GetTCPConn()
	default:
		logger.Debug("failed case connection type")
		return
	}

	if err := tcpConn.SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on downstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on downstream connection")
	}

	if err := upstreamConn.(*net.TCPConn).SetNoDelay(true); err != nil {
		logger.Debug("failed to set nodelay on upstream connection", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("successfully set NoDelay on upstream connection")
	}

	for len(restBytes) > 0 {
		n, err := upstreamConn.Write(restBytes)
		if err != nil {
			logger.Debug("failed to write data to upstream connection",
				zap.Error(err), zap.Bool("dropConnection", true))
			return
		}
		restBytes = restBytes[n:]
	}

	outErr := make(chan error, 2)
	go tcpCopyData(upstreamConn, conn, outErr)
	go tcpCopyData(conn, upstreamConn, outErr)

	err = <-outErr
	if err != nil {
		logger.Debug("connection broken", zap.Error(err), zap.Bool("dropConnection", true))
	} else if Opts.Verbose > 1 {
		logger.Debug("connection closing")
	}
}

func TCPListen(listenConfig *net.ListenConfig, logger *zap.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.Listen(ctx, "tcp", Opts.ListenAddr)
	if err != nil {
		logger.Error("failed to bind listener", zap.Error(err))
		errors <- err
		return
	}

	addrFn := getProxyAddr
	if Opts.RawProxy {
		addrFn = getRawAddr
	}

	logger.Info("listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("failed to accept new connection", zap.Error(err))
			errors <- err
			return
		}

		if Opts.RatelimitProxyRx > 0 || Opts.RatelimitProxyTx > 0 {
			rx := Opts.RatelimitProxyRx
			tx := Opts.RatelimitProxyTx
			conn = NewSpeedCtrl(conn, rx, rx * 8, tx, tx * 16)
		}

		go tcpHandleConnection(conn, logger, addrFn)
	}
}
