package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeBatchProverHappyPath(t *testing.T) {
	curve := curves.ED25519()
	n := 256
	prover, err := NewRangeProver(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v1 := curve.Scalar.Random(crand.Reader)
	v2 := curve.Scalar.Random(crand.Reader)
	v3 := curve.Scalar.Random(crand.Reader)
	v4 := curve.Scalar.Random(crand.Reader)
	v := []curves.Scalar{v1, v2, v3, v4}

	gamma1 := curve.Scalar.Random(crand.Reader)
	gamma2 := curve.Scalar.Random(crand.Reader)
	gamma3 := curve.Scalar.Random(crand.Reader)
	gamma4 := curve.Scalar.Random(crand.Reader)
	gamma := []curves.Scalar{gamma1, gamma2, gamma3, gamma4}
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.BatchProve(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.Equal(t, 10, len(proof.ipp.capLs))
	require.Equal(t, 10, len(proof.ipp.capRs))
}

func TestGetaLBatched(t *testing.T) {
	curve := curves.ED25519()
	v1 := curve.Scalar.Random(crand.Reader)
	v2 := curve.Scalar.Random(crand.Reader)
	v3 := curve.Scalar.Random(crand.Reader)
	v4 := curve.Scalar.Random(crand.Reader)
	v := []curves.Scalar{v1, v2, v3, v4}
	aL, err := getaLBatched(v, 256, *curve)
	require.NoError(t, err)
	twoN := get2nVector(256, *curve)
	for i := 1; i < len(v)+1; i++ {
		vec := aL[(i-1)*256 : i*256]
		product, err := innerProduct(vec, twoN)
		require.NoError(t, err)
		require.Zero(t, product.Cmp(v[i-1]))
	}
}

func TestRangeBatchProverMarshal(t *testing.T) {
	curve := curves.ED25519()
	n := 256
	prover, err := NewRangeProver(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v1 := curve.Scalar.Random(crand.Reader)
	v2 := curve.Scalar.Random(crand.Reader)
	v3 := curve.Scalar.Random(crand.Reader)
	v4 := curve.Scalar.Random(crand.Reader)
	v := []curves.Scalar{v1, v2, v3, v4}

	gamma1 := curve.Scalar.Random(crand.Reader)
	gamma2 := curve.Scalar.Random(crand.Reader)
	gamma3 := curve.Scalar.Random(crand.Reader)
	gamma4 := curve.Scalar.Random(crand.Reader)
	gamma := []curves.Scalar{gamma1, gamma2, gamma3, gamma4}
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.BatchProve(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	proofMarshaled := proof.MarshalBinary()
	proofPrime := NewRangeProof(curve)
	err = proofPrime.UnmarshalBinary(proofMarshaled)
	require.NoError(t, err)
	require.True(t, proof.capA.Equal(proofPrime.capA))
	require.True(t, proof.capS.Equal(proofPrime.capS))
	require.True(t, proof.capT1.Equal(proofPrime.capT1))
	require.True(t, proof.capT2.Equal(proofPrime.capT2))
	require.Zero(t, proof.taux.Cmp(proofPrime.taux))
	require.Zero(t, proof.mu.Cmp(proofPrime.mu))
	require.Zero(t, proof.tHat.Cmp(proofPrime.tHat))
}
