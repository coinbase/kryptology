//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import (
	"fmt"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func testDKG(alice *Alice, bob *Bob, alicePipe *pipeWrapper, bobPipe *pipeWrapper) error {
	errors := make(chan error, 2)

	go func() {
		errors <- alice.DKG(alicePipe)
	}()
	go func() {
		errors <- bob.DKG(bobPipe)
	}()
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			return err // leakage? what if the second goroutine is "suspended"?
		}
	}
	return verifyOt(alice, bob)
}

func TestDKG(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.Nil(t, err)
	alice := NewAlice(params)
	bob := NewBob(params)

	alicePipe, bobPipe := NewPipeWrappers()
	require.Nil(t, testDKG(alice, bob, alicePipe, bobPipe))
}

func BenchmarkDKG(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}

	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.Nil(b, err)
	alice := NewAlice(params)
	bob := NewBob(params)
	b.ResetTimer()
	bytes := 0
	for n := 0; n < b.N; n++ {
		alicePipe, bobPipe := NewPipeWrappers()
		require.Nil(b, testDKG(alice, bob, alicePipe, bobPipe))
		bytes += alicePipe.exchanged
	}
	b.ReportMetric(float64(bytes)/float64(b.N), "bytes/op")
}

// Verify correctness of the OT subprotocol after DKG has completed
func verifyOt(alice *Alice, bob *Bob) error {
	for i := 0; i < kappa; i++ {
		if alice.Receiver.Rho[i] != bob.Sender.Rho[i][alice.Receiver.choice[i]] {
			return fmt.Errorf("oblivious transfer is incorrect at index i=%v", i)
		}
	}
	return nil
}
