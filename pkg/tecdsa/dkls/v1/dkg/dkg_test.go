//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkg

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/ot/extension/kos"

	"github.com/coinbase/kryptology/pkg/core/curves"

	"github.com/stretchr/testify/require"
)

func TestDkg(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		alice := NewAlice(curve)
		bob := NewBob(curve)

		seed, err := bob.Round1GenerateRandomSeed()
		require.NoError(t, err)
		round3Output, err := alice.Round2CommitToProof(seed)
		require.NoError(t, err)
		proof, err := bob.Round3SchnorrProve(round3Output)
		require.NoError(t, err)
		proof, err = alice.Round4VerifyAndReveal(proof)
		require.NoError(t, err)
		proof, err = bob.Round5DecommitmentAndStartOt(proof)
		require.NoError(t, err)
		compressedReceiversMaskedChoice, err := alice.Round6DkgRound2Ot(proof)
		require.NoError(t, err)
		challenge, err := bob.Round7DkgRound3Ot(compressedReceiversMaskedChoice)
		require.NoError(t, err)
		challengeResponse, err := alice.Round8DkgRound4Ot(challenge)
		require.NoError(t, err)
		challengeOpenings, err := bob.Round9DkgRound5Ot(challengeResponse)
		require.NoError(t, err)
		err = alice.Round10DkgRound6Ot(challengeOpenings)
		require.NoError(t, err)

		// Verify correctness of the OT subprotocol after  has completed
		for i := 0; i < kos.Kappa; i++ {
			if alice.receiver.Output.OneTimePadDecryptionKey[i] != bob.sender.Output.OneTimePadEncryptionKeys[i][alice.receiver.Output.RandomChoiceBits[i]] {
				t.Errorf("oblivious transfer is incorrect at index i=%v", i)
			}
		}

		pkA := curve.ScalarBaseMult(alice.Output().SecretKeyShare)
		pkB := curve.ScalarBaseMult(bob.Output().SecretKeyShare)

		computedPublicKeyA := pkA.Mul(bob.Output().SecretKeyShare)
		require.True(t, computedPublicKeyA.Equal(alice.Output().PublicKey))
		require.True(t, computedPublicKeyA.Equal(bob.Output().PublicKey))

		computedPublicKeyB := pkB.Mul(alice.Output().SecretKeyShare)
		require.True(t, computedPublicKeyB.Equal(alice.Output().PublicKey))
		require.True(t, computedPublicKeyB.Equal(bob.Output().PublicKey))
	}
}

func BenchmarkDkg(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}
	curve := curves.K256()

	for n := 0; n < b.N; n++ {
		alice := NewAlice(curve)
		bob := NewBob(curve)

		seed, err := bob.Round1GenerateRandomSeed()
		require.NoError(b, err)
		round3Output, err := alice.Round2CommitToProof(seed)
		require.NoError(b, err)
		proof, err := bob.Round3SchnorrProve(round3Output)
		require.NoError(b, err)
		proof, err = alice.Round4VerifyAndReveal(proof)
		require.NoError(b, err)
		proof, err = bob.Round5DecommitmentAndStartOt(proof)
		require.NoError(b, err)
		compressedReceiversMaskedChoice, err := alice.Round6DkgRound2Ot(proof)
		require.NoError(b, err)
		challenge, err := bob.Round7DkgRound3Ot(compressedReceiversMaskedChoice)
		require.NoError(b, err)
		challengeResponse, err := alice.Round8DkgRound4Ot(challenge)
		require.NoError(b, err)
		challengeOpenings, err := bob.Round9DkgRound5Ot(challengeResponse)
		require.NoError(b, err)
		err = alice.Round10DkgRound6Ot(challengeOpenings)
		require.NoError(b, err)
	}
}
