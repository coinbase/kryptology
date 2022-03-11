//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package simplest_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/ottest"
)

func TestOtOnMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		batchSize := 256
		hashKeySeed := [32]byte{}
		_, err := rand.Read(hashKeySeed[:])
		require.NoError(t, err)
		sender, receiver, err := ottest.RunSimplestOT(curve, batchSize, hashKeySeed)
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			require.Equal(t, receiver.OneTimePadDecryptionKey[i], sender.OneTimePadEncryptionKeys[i][receiver.RandomChoiceBits[i]])
		}

		// Transfer messages
		messages := make([][2][32]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			messages[i] = [2][32]byte{
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][0]", i))),
				sha256.Sum256([]byte(fmt.Sprintf("message[%d][1]", i))),
			}
		}
		ciphertexts, err := sender.Encrypt(messages)
		require.NoError(t, err)
		decrypted, err := receiver.Decrypt(ciphertexts)
		require.NoError(t, err)

		for i := 0; i < batchSize; i++ {
			choice := receiver.RandomChoiceBits[i]
			require.Equal(t, messages[i][choice], decrypted[i])
			require.NotEqual(t, messages[i][1-choice], decrypted[i])
		}
	}
}

func TestOTStreaming(t *testing.T) {
	batchSize := 256
	curve := curves.K256()
	hashKeySeed := [32]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)
	sender, err := simplest.NewSender(curve, batchSize, hashKeySeed)
	require.Nil(t, err)
	receiver, err := simplest.NewReceiver(curve, batchSize, hashKeySeed)
	require.Nil(t, err)

	senderPipe, receiverPipe := simplest.NewPipeWrappers()
	errorsChannel := make(chan error, 2) // warning: if one party errors, the other will sit there forever. add timeouts.
	go func() {
		errorsChannel <- simplest.SenderStreamOTRun(sender, senderPipe)
	}()
	go func() {
		errorsChannel <- simplest.ReceiverStreamOTRun(receiver, receiverPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errorsChannel)
	}
	for i := 0; i < batchSize; i++ {
		require.Equal(t, receiver.Output.OneTimePadDecryptionKey[i], sender.Output.OneTimePadEncryptionKeys[i][receiver.Output.RandomChoiceBits[i]])
	}
}
