//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"crypto/sha256"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.NoError(t, err)
	alice := NewAlice(params)
	bob := NewBob(params)

	alicePipe, bobPipe := NewPipeWrappers()
	require.NoError(t, testDKG(alice, bob, alicePipe, bobPipe))
	require.NoError(t, testSign(alice, bob, alicePipe, bobPipe))
}

func BenchmarkSign(b *testing.B) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.NoError(b, err)
	alice := NewAlice(params)
	bob := NewBob(params)
	alicePipe, bobPipe := NewPipeWrappers()
	require.NoError(b, testDKG(alice, bob, alicePipe, bobPipe))
	b.ResetTimer()
	bytes := 0
	for n := 0; n < b.N; n++ {
		alicePipe, bobPipe = NewPipeWrappers()
		require.NoError(b, testSign(alice, bob, alicePipe, bobPipe))
		bytes += alicePipe.exchanged
	}
	b.ReportMetric(float64(bytes)/float64(b.N), "bytes/op")
}

// Helper function that runs signing
func testSign(alice *Alice, bob *Bob, alicePipe *pipeWrapper, bobPipe *pipeWrapper) error {
	// ^^^ a bit clunky that we have to pass these in, but i don't see an easier way as far as benchmarking the bytes
	errors := make(chan error, 2) // warning: if one party errors, the other will sit there forever. add timeouts.

	m := []byte("Our mission is to increase economic freedom in the world.")
	digest := sha256.Sum256(m)
	go func() {
		errors <- alice.Sign(digest[:], alicePipe)
	}()
	go func() {
		errors <- bob.Sign(digest[:], bobPipe)
	}()
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			return err
		}
	}
	return nil
}
