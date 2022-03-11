package dealer_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dealer"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
)

func Test_DealerCanGenerateKeysThatSign(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		aliceOutput, bobOutput, err := dealer.GenerateAndDeal(curve)
		require.NoError(t, err)

		alice := sign.NewAlice(curve, sha3.New256(), aliceOutput)
		bob := sign.NewBob(curve, sha3.New256(), bobOutput)

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

func Test_DealerGeneratesDifferentResultsEachTime(t *testing.T) {
	curve := curves.K256()
	aliceOutput1, bobOutput1, err := dealer.GenerateAndDeal(curve)
	require.NoError(t, err)
	aliceOutput2, bobOutput2, err := dealer.GenerateAndDeal(curve)
	require.NoError(t, err)

	require.NotEqual(t, aliceOutput1.SecretKeyShare, aliceOutput2.SecretKeyShare)
	require.NotEqual(t, bobOutput1.SecretKeyShare, bobOutput2.SecretKeyShare)
	require.NotEqualValues(t, aliceOutput1.SeedOtResult.RandomChoiceBits, aliceOutput2.SeedOtResult.RandomChoiceBits)
	require.NotEqualValues(t, bobOutput1.SeedOtResult.OneTimePadEncryptionKeys, bobOutput2.SeedOtResult.OneTimePadEncryptionKeys)
}
