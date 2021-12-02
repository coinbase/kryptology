//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"math/big"
)

func bigFromHex(hex string) *big.Int {
	if len(hex) > 1 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	n, success := new(big.Int).SetString(hex, 16)
	if !success {
		panic("bigFromHex: failed to convert hex to big")
	}
	return n
}
