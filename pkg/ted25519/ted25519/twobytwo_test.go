//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

/*
* This is a simple example of a 2x2 signature scheme to prove out a simpler case than the threshold
* variants. We don't intend to use it and it is not modeled off of any specific known protocol.
 */
package ted25519

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/assert"
	"testing"
)

func AggregateSignatures(sig1, sig2 *PartialSignature) []byte {
	field := curves.NewField(curves.Ed25519Order())
	sig1s := field.ElementFromBytes(reverseBytes(sig1.S()))
	sig2s := field.ElementFromBytes(reverseBytes(sig2.S()))
	sigS := sig1s.Add(sig2s)

	// Create signature as R || s. The R is the same so we use the same one
	sig := make([]byte, SignatureSize)
	copy(sig, sig1.R())
	copy(sig[32:], reverseBytes(sigS.Bytes()))
	return sig
}

func TestTwoByTwoSigning(t *testing.T) {
	// generate shared pubkey
	pub1, priv1, _ := generateSharableKey()
	pub2, priv2, _ := generateSharableKey()
	pub := GeAdd(pub1, pub2)

	// generate shared nonce
	pubr1, r1, _ := generateSharableKey()
	pubr2, r2, _ := generateSharableKey()
	noncePub := GeAdd(pubr1, pubr2)

	// generate partial sigs
	msg := []byte("test message")
	sig1 := TSign(msg, NewKeyShare(0, priv1), pub, NewNonceShare(0, r1), noncePub)
	sig2 := TSign(msg, NewKeyShare(0, priv2), pub, NewNonceShare(0, r2), noncePub)

	// add sigs (s+s)
	sig := AggregateSignatures(sig1, sig2)

	ok, _ := Verify(pub, msg, sig)
	assert.True(t, ok, "signature failed verification")
}
