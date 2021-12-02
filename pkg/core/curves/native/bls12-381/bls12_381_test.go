//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"math/big"
	"os"
	"testing"
)

var fuz int

func TestMain(m *testing.M) {
	_fuz := flag.Int("fuzz", 10, "# of iterations")
	flag.Parse()
	fuz = *_fuz
	m.Run()
	os.Exit(0)
}

func randScalar(max *big.Int) *big.Int {
	a, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.New(""))
	}
	return a
}

//func randScalars(max *big.Int, size int) []*big.Int {
//	var scalars []*big.Int
//	for i := 0; i < size; i++ {
//		a, err := rand.Int(rand.Reader, max)
//		if err != nil {
//			panic(errors.New(""))
//		}
//		scalars = append(scalars, a)
//	}
//	return scalars
//}

func fromHex(size int, hexStrs ...string) []byte {
	var out []byte
	if size > 0 {
		out = make([]byte, size*len(hexStrs))
	}
	for i := 0; i < len(hexStrs); i++ {
		hexStr := hexStrs[i]
		if hexStr[:2] == "0x" {
			hexStr = hexStr[2:]
		}
		if len(hexStr)%2 == 1 {
			hexStr = "0" + hexStr
		}
		bytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil
		}
		if size <= 0 {
			out = append(out, bytes...)
		} else {
			if len(bytes) > size {
				return nil
			}
			offset := i*size + (size - len(bytes))
			copy(out[offset:], bytes)
		}
	}
	return out
}
