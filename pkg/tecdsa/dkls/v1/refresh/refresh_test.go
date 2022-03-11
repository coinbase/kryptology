//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package refresh_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/refresh"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
)

func performDKG(t *testing.T, curve *curves.Curve) (*dkg.Alice, *dkg.Bob) {
	t.Helper()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

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

	return alice, bob
}

func performRefresh(t *testing.T, curve *curves.Curve, aliceSecretKeyShare, bobSecretKeyShare curves.Scalar) (*refresh.Alice, *refresh.Bob) {
	t.Helper()
	alice := refresh.NewAlice(curve, &dkg.AliceOutput{SecretKeyShare: aliceSecretKeyShare})
	bob := refresh.NewBob(curve, &dkg.BobOutput{SecretKeyShare: bobSecretKeyShare})

	round1Output := alice.Round1RefreshGenerateSeed()
	require.False(t, round1Output.IsZero())
	round2Output, err := bob.Round2RefreshProduceSeedAndMultiplyAndStartOT(round1Output)
	require.NoError(t, err)
	round3Output, err := alice.Round3RefreshMultiplyRound2Ot(round2Output)
	require.NoError(t, err)
	round4Output, err := bob.Round4RefreshRound3Ot(round3Output)
	require.NoError(t, err)
	round5Output, err := alice.Round5RefreshRound4Ot(round4Output)
	require.NoError(t, err)
	round6Output, err := bob.Round6RefreshRound5Ot(round5Output)
	require.NoError(t, err)
	err = alice.Round7DkgRound6Ot(round6Output)
	require.NoError(t, err)
	return alice, bob
}

func Test_RefreshLeadsToTheSamePublicKeyButDifferentPrivateMaterial(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		boundCurve := curve
		t.Run(fmt.Sprintf("testing refresh for curve %s", boundCurve.Name), func(tt *testing.T) {
			tt.Parallel()
			alice, bob := performDKG(tt, boundCurve)

			publicKey := alice.Output().PublicKey
			require.True(tt, publicKey.Equal(bob.Output().PublicKey))

			aliceRefreshed, bobRefreshed := performRefresh(tt, boundCurve, alice.Output().SecretKeyShare, bob.Output().SecretKeyShare)

			require.NotEqual(tt, aliceRefreshed.Output().SecretKeyShare, alice.Output().SecretKeyShare)
			require.NotEqual(tt, bobRefreshed.Output().SeedOtResult, bob.Output().SecretKeyShare)
			require.NotEqualValues(
				tt,
				aliceRefreshed.Output().SeedOtResult.OneTimePadDecryptionKey,
				alice.Output().SeedOtResult.OneTimePadDecryptionKey,
			)
			require.NotEqualValues(
				tt,
				aliceRefreshed.Output().SeedOtResult.PackedRandomChoiceBits,
				alice.Output().SeedOtResult.PackedRandomChoiceBits,
			)
			require.NotEqualValues(
				tt,
				aliceRefreshed.Output().SeedOtResult.RandomChoiceBits,
				alice.Output().SeedOtResult.RandomChoiceBits,
			)
			require.NotEqualValues(
				tt,
				bobRefreshed.Output().SeedOtResult.OneTimePadEncryptionKeys,
				bob.Output().SeedOtResult.OneTimePadEncryptionKeys,
			)

			pkA := boundCurve.ScalarBaseMult(aliceRefreshed.Output().SecretKeyShare)
			computedPublicKeyA := pkA.Mul(bobRefreshed.Output().SecretKeyShare)
			require.True(tt, computedPublicKeyA.Equal(publicKey))

			pkB := boundCurve.ScalarBaseMult(bobRefreshed.Output().SecretKeyShare)
			computedPublicKeyB := pkB.Mul(aliceRefreshed.Output().SecretKeyShare)
			require.True(tt, computedPublicKeyB.Equal(publicKey))
		})
	}
}

func Test_RefreshOTIsCorrect(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		boundCurve := curve
		t.Run(fmt.Sprintf("testing OT correctness of key refresh for curve %s", boundCurve.Name), func(tt *testing.T) {
			tt.Parallel()
			alice, bob := performDKG(tt, boundCurve)
			aliceRefreshed, bobRefreshed := performRefresh(tt, boundCurve, alice.Output().SecretKeyShare, bob.Output().SecretKeyShare)
			for i := 0; i < kos.Kappa; i++ {
				if aliceRefreshed.Output().SeedOtResult.OneTimePadDecryptionKey[i] != bobRefreshed.Output().SeedOtResult.OneTimePadEncryptionKeys[i][aliceRefreshed.Output().SeedOtResult.RandomChoiceBits[i]] {
					tt.Errorf("oblivious transfer is incorrect at index i=%v", i)
				}
			}

		})
	}

}

func Test_CanSignAfterRefresh(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		boundCurve := curve
		t.Run(fmt.Sprintf("testing sign after refresh for curve %s", boundCurve.Name), func(tt *testing.T) {
			tt.Parallel()
			aliceDKG, bobDKG := performDKG(tt, boundCurve)

			publicKey := aliceDKG.Output().PublicKey
			require.True(tt, publicKey.Equal(bobDKG.Output().PublicKey))

			aliceRefreshed, bobRefreshed := performRefresh(tt, boundCurve, aliceDKG.Output().SecretKeyShare, bobDKG.Output().SecretKeyShare)

			alice := sign.NewAlice(boundCurve, sha3.New256(), &dkg.AliceOutput{
				SeedOtResult:   aliceRefreshed.Output().SeedOtResult,
				SecretKeyShare: aliceRefreshed.Output().SecretKeyShare,
				PublicKey:      publicKey,
			})
			bob := sign.NewBob(boundCurve, sha3.New256(), &dkg.BobOutput{
				SeedOtResult:   bobRefreshed.Output().SeedOtResult,
				SecretKeyShare: bobRefreshed.Output().SecretKeyShare,
				PublicKey:      publicKey,
			})

			message := []byte("A message.")
			seed, err := alice.Round1GenerateRandomSeed()
			require.NoError(tt, err)
			round3Output, err := bob.Round2Initialize(seed)
			require.NoError(tt, err)
			round4Output, err := alice.Round3Sign(message, round3Output)
			require.NoError(tt, err)
			err = bob.Round4Final(message, round4Output)
			require.NoError(tt, err, "curve: %s", boundCurve.Name)
		})
	}
}
