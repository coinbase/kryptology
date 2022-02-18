package kos

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/ot/ottest"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/stretchr/testify/require"
)

func TestCOTExtension(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		sender := NewCOtSender(baseOtReceiverOutput, curve)
		receiver := NewCOtReceiver(baseOtSenderOutput, curve)
		choice := [COtBlockSizeBytes]byte{} // receiver's input, namely choice vector. just random
		_, err = rand.Read(choice[:])
		require.NoError(t, err)
		input := [L][OtWidth]curves.Scalar{} // sender's input, namely integer "sums" in case w_j == 1.
		for i := 0; i < L; i++ {
			for j := 0; j < OtWidth; j++ {
				input[i][j] = curve.Scalar.Random(rand.Reader)
				require.NoError(t, err)
			}
		}
		firstMessage, err := receiver.Round1Initialize(uniqueSessionId, choice)
		require.NoError(t, err)
		responseTau, err := sender.Round2Transfer(uniqueSessionId, input, firstMessage)
		require.NoError(t, err)
		err = receiver.Round3Transfer(responseTau)
		require.NoError(t, err)
		for j := 0; j < L; j++ {
			bit := simplest.ExtractBitFromByteVector(choice[:], j) == 1
			for k := 0; k < OtWidth; k++ {
				temp := sender.OutputAdditiveShares[j][k].Add(receiver.OutputAdditiveShares[j][k])
				if bit {
					require.Zero(t, temp.Cmp(input[j][k]))
				} else {
					require.Zero(t, temp.Cmp(curve.Scalar.Zero()))
				}
			}
		}
	}
}

func TestCOTExtensionStreaming(t *testing.T) {
	curve := curves.K256()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)
	baseOtReceiver, err := simplest.NewReceiver(curve, Kappa, hashKeySeed)
	require.NoError(t, err)
	sender := NewCOtSender(baseOtReceiver.Output, curve)
	baseOtSender, err := simplest.NewSender(curve, Kappa, hashKeySeed)
	require.NoError(t, err)
	receiver := NewCOtReceiver(baseOtSender.Output, curve)

	// first run the seed OT
	senderPipe, receiverPipe := simplest.NewPipeWrappers()
	errorsChannel := make(chan error, 2)
	go func() {
		errorsChannel <- simplest.SenderStreamOTRun(baseOtSender, senderPipe)
	}()
	go func() {
		errorsChannel <- simplest.ReceiverStreamOTRun(baseOtReceiver, receiverPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errorsChannel)
	}
	for i := 0; i < Kappa; i++ {
		require.Equal(t, baseOtReceiver.Output.OneTimePadDecryptionKey[i], baseOtSender.Output.OneTimePadEncryptionKeys[i][baseOtReceiver.Output.RandomChoiceBits[i]])
	}

	// begin test of cOT extension. first populate both parties' inputs randomly
	choice := [COtBlockSizeBytes]byte{} // receiver's input, namely choice vector. just random
	_, err = rand.Read(choice[:])
	require.NoError(t, err)
	input := [L][OtWidth]curves.Scalar{} // sender's input, namely integer "sums" in case w_j == 1. random for the test
	for i := 0; i < L; i++ {
		for j := 0; j < OtWidth; j++ {
			input[i][j] = curve.Scalar.Random(rand.Reader)
			require.NoError(t, err)
		}
	}

	// now actually run it, stream-wise
	go func() {
		errorsChannel <- SenderStreamCOtRun(sender, hashKeySeed, input, receiverPipe)
	}()
	go func() {
		errorsChannel <- ReceiverStreamCOtRun(receiver, hashKeySeed, choice, senderPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errorsChannel)
	}
	for j := 0; j < L; j++ {
		bit := simplest.ExtractBitFromByteVector(choice[:], j) == 1
		for k := 0; k < OtWidth; k++ {
			temp := sender.OutputAdditiveShares[j][k].Add(receiver.OutputAdditiveShares[j][k])
			if bit {
				require.Zero(t, temp.Cmp(input[j][k]))
			} else {
				require.Zero(t, temp.Cmp(curve.Scalar.Zero()))
			}
		}
	}
}
