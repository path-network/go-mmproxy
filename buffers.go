// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"math"
	"sync"
)

var buffers sync.Pool

func init() {
	buffers.New = func() interface{} { return make([]byte, math.MaxUint16) }
}

func GetBuffer() []byte {
	return buffers.Get().([]byte)
}

func PutBuffer(buf []byte) {
	buffers.Put(buf)
}
