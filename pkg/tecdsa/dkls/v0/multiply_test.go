//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestMultiply(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.Nil(t, err)
	const multiplicity = 2
	sender := NewMultiplySender(multiplicity, &seedOTReceiver{params: params})
	receiver := NewMultiplyReceiver(multiplicity, &seedOTSender{params: params})

	senderPipe, receiverPipe := NewPipeWrappers()
	errors := make(chan error, 2) // warning: if one party errors, the other will sit there forever. add timeouts.
	go func() {
		errors <- sender.sender.receiver.kosSetup(senderPipe)
	}()
	go func() {
		errors <- receiver.receiver.sender.kosSetup(receiverPipe)
	}()
	// warning: will these goroutines above "leak" if one errors and the other is waiting?
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errors)
	}
	for i := 0; i < kappa; i++ {
		require.Equal(t, sender.sender.receiver.Rho[i], receiver.receiver.sender.Rho[i][sender.sender.receiver.choice[i]])
	}
	alpha := [multiplicity]*big.Int{}
	beta := [multiplicity]*big.Int{}
	for i := 0; i < multiplicity; i++ {
		alpha[i], err = params.Scalar.Random()
		require.Nil(t, err)
		beta[i], err = params.Scalar.Random()
		require.Nil(t, err)
	}
	idExt := [32]byte{}
	_, err = rand.Read(idExt[:])
	require.Nil(t, err)
	go func() {
		errors <- sender.multiply(idExt, alpha[:], senderPipe)
	}()
	go func() {
		errors <- receiver.multiply(idExt, beta[:], receiverPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errors)
	}
	for i := 0; i < multiplicity; i++ {
		product := params.Scalar.Mul(alpha[i], beta[i])
		sum := params.Scalar.Add(sender.TA[i], receiver.TB[i])
		require.Zero(t, product.Cmp(sum))
	}
}
