package schnorr

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		curves.PALLAS(),
		curves.BLS12377G1(),
		curves.BLS12377G2(),
		curves.BLS12381G1(),
		curves.BLS12381G2(),
		curves.ED25519(),
	}
	for i, curve := range curveInstances {
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover := NewProver(curve, nil, uniqueSessionId)

		secret := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(secret)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, nil, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
