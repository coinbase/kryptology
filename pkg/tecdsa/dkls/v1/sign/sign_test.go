//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sign

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/ot/ottest"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
)

func TestSign(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		hashKeySeed := [simplest.DigestSize]byte{}
		_, err := rand.Read(hashKeySeed[:])
		require.NoError(t, err)

		baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, kos.Kappa, hashKeySeed)
		require.NoError(t, err)

		secretKeyShareA := curve.Scalar.Random(rand.Reader)
		secretKeyShareB := curve.Scalar.Random(rand.Reader)
		require.NoError(t, err)
		publicKey := curve.ScalarBaseMult(secretKeyShareA.Mul(secretKeyShareB))
		alice := NewAlice(curve, sha3.New256(), &dkg.AliceOutput{SeedOtResult: baseOtReceiverOutput, SecretKeyShare: secretKeyShareA, PublicKey: publicKey})
		bob := NewBob(curve, sha3.New256(), &dkg.BobOutput{SeedOtResult: baseOtSenderOutput, SecretKeyShare: secretKeyShareB, PublicKey: publicKey})

		message := []byte("A message.")
		seed, err := alice.Round1GenerateRandomSeed()
		require.NoError(t, err)
		round3Output, err := bob.Round2Initialize(seed)
		require.NoError(t, err)
		round4Output, err := alice.Round3Sign(message, round3Output)
		require.NoError(t, err)
		err = bob.Round4Final(message, round4Output)
		require.NoError(t, err, "curve: %s", curve.Name)
	}
}

func BenchmarkSign(b *testing.B) {
	curve := curves.K256()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(b, err)

	baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, kos.Kappa, hashKeySeed)
	require.NoError(b, err)

	secretKeyShareA := curve.Scalar.Random(rand.Reader)
	secretKeyShareB := curve.Scalar.Random(rand.Reader)
	publicKey := curve.ScalarBaseMult(secretKeyShareA.Mul(secretKeyShareB))
	alice := NewAlice(curve, sha3.New256(), &dkg.AliceOutput{SeedOtResult: baseOtReceiverOutput, SecretKeyShare: secretKeyShareA, PublicKey: publicKey})
	bob := NewBob(curve, sha3.New256(), &dkg.BobOutput{SeedOtResult: baseOtSenderOutput, SecretKeyShare: secretKeyShareB, PublicKey: publicKey})

	message := []byte("A message.")
	for n := 0; n < b.N; n++ {
		seed, err := alice.Round1GenerateRandomSeed()
		require.NoError(b, err)
		round3Output, err := bob.Round2Initialize(seed)
		require.NoError(b, err)
		round4Output, err := alice.Round3Sign(message, round3Output)
		require.NoError(b, err)
		err = bob.Round4Final(message, round4Output)
		require.NoError(b, err)
	}
}
