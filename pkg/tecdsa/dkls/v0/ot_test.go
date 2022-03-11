//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestSeedOT(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.Nil(t, err)
	sender := &seedOTSender{params: params}
	receiver := &seedOTReceiver{params: params}

	senderPipe, receiverPipe := NewPipeWrappers()
	errors := make(chan error, 2) // warning: if one party errors, the other will sit there forever. add timeouts.
	go func() {
		errors <- sender.kosSetup(senderPipe)
	}()
	go func() {
		errors <- receiver.kosSetup(receiverPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errors)
	}
	for i := 0; i < kappa; i++ {
		require.Equal(t, receiver.Rho[i], sender.Rho[i][receiver.choice[i]])
	}
}

func TestCOTExtension(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.Nil(t, err)
	const multiplicity = 2
	sender := newCOTSender(multiplicity, &seedOTReceiver{params: params})
	receiver := newCOTReceiver(multiplicity, &seedOTSender{params: params})

	senderPipe, receiverPipe := NewPipeWrappers()
	errors := make(chan error, 2) // warning: if one party errors, the other will sit there forever. add timeouts.
	go func() {
		errors <- receiver.sender.kosSetup(receiverPipe)
	}()
	go func() {
		errors <- sender.receiver.kosSetup(senderPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errors)
	}
	for i := 0; i < kappa; i++ {
		require.Equal(t, sender.receiver.Rho[i], receiver.sender.Rho[i][sender.receiver.choice[i]])
	}
	idExt := [32]byte{}
	_, err = rand.Read(idExt[:])
	require.Nil(t, err)
	choice := make([]byte, receiver.l>>3) // Bob's
	_, err = rand.Read(choice[:])
	require.Nil(t, err)
	input := [2 * kappa * multiplicity]*big.Int{} // Alice's
	inputOT := [2 * s][]*big.Int{}                // Alice's
	for i := 0; i < 2*s; i++ {
		inputOT[i] = make([]*big.Int, multiplicity)
	}
	for j := 0; j < 2*kappa*multiplicity; j++ {
		input[j], err = params.Scalar.Random()
		require.Nil(t, err)
	}
	for j := 0; j < 2*s; j++ {
		for k := 0; k < multiplicity; k++ {
			inputOT[j][k], err = params.Scalar.Random()
			require.Nil(t, err)
		}
	}
	go func() {
		errors <- receiver.cOT(idExt, choice, receiverPipe)
	}()
	go func() {
		errors <- sender.cOT(idExt, input[:], inputOT, senderPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errors)
	}
	for j := 0; j < 2*kappa*multiplicity; j++ {
		bit := choice[j>>3]>>(j&0x07)&0x01 == 1
		temp := params.Scalar.Add(sender.tA[j], receiver.tB[j])
		if bit {
			require.Equal(t, temp, input[j])
		} else {
			require.Zero(t, temp.Cmp(new(big.Int)))
		}
	}
	for j := 0; j < 2*s; j++ {
		bit := choice[(2*kappa*multiplicity+j)>>3]>>(j&0x07)&0x01 == 1
		for k := 0; k < multiplicity; k++ {
			temp := params.Scalar.Add(sender.tAOT[j][k], receiver.tBOT[j][k])
			if bit {
				require.Equal(t, temp, inputOT[j][k])
			} else {
				require.Zero(t, temp.Cmp(new(big.Int)))
			}
		}
	}
}
