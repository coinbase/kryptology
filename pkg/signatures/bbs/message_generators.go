//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// MessageGenerators are used to sign a vector of commitments for
// a BBS+ signature. These must be the same generators used by
// sign, verify, prove, and open
//
// These are generated in a deterministic manner. By using
// MessageGenerators in this way, the generators do not need to be
// stored alongside the public key and the same key can be used to sign
// an arbitrary number of messages
// Generators are created by computing
// H_i = H_G1(W || I2OSP(0, 4) || I2OSP(0, 1) || I2OSP(length, 4))
// where I2OSP means Integer to Octet Stream Primitive and
// I2OSP represents an integer in a statically sized byte array.
// `W` is the BBS+ public key.
// Internally we store the 201 byte state since the only value that changes
// is the index
type MessageGenerators struct {
	// Blinding factor generator, stored, so we know what points to return in `Get`
	h0     curves.PairingPoint
	length int
	state  [201]byte
}

// Init set the message generators to the default state
func (msgg *MessageGenerators) Init(w *PublicKey, length int) *MessageGenerators {
	if length < 0 {
		return nil
	}
	msgg.length = length
	for i := range msgg.state {
		msgg.state[i] = 0
	}
	copy(msgg.state[:192], w.value.ToAffineUncompressed())
	msgg.state[197] = byte(length >> 24)
	msgg.state[198] = byte(length >> 16)
	msgg.state[199] = byte(length >> 8)
	msgg.state[200] = byte(length)
	msgg.h0 = w.value.OtherGroup().Hash(msgg.state[:]).(curves.PairingPoint)

	return msgg
}

func (msgg MessageGenerators) Get(i int) curves.PairingPoint {
	if i <= 0 {
		return msgg.h0
	}
	if i > msgg.length {
		return nil
	}
	state := msgg.state
	state[193] = byte(i >> 24)
	state[194] = byte(i >> 16)
	state[195] = byte(i >> 8)
	state[196] = byte(i)
	return msgg.h0.Hash(msgg.state[:]).(curves.PairingPoint)
}
