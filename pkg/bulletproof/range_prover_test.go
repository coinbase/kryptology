package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeProverHappyPath(t *testing.T) {
	curve := curves.ED25519()
	n := 256
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.Random(crand.Reader)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.Equal(t, 8, len(proof.ipp.capLs))
	require.Equal(t, 8, len(proof.ipp.capRs))
}

func TestGetaL(t *testing.T) {
	curve := curves.ED25519()
	v := curve.Scalar.Random(crand.Reader)
	aL, err := getaL(v, 256, *curve)
	require.NoError(t, err)
	twoN := get2nVector(256, *curve)
	product, err := innerProduct(aL, twoN)
	require.NoError(t, err)
	require.Zero(t, product.Cmp(v))
}

func TestCmove(t *testing.T) {
	curve := curves.ED25519()
	two := curve.Scalar.One().Double()
	four := two.Double()
	out, err := cmoveScalar(two, four, 1, *curve)
	require.NoError(t, err)
	require.Zero(t, out.Cmp(four))
}

func TestRangeProverMarshal(t *testing.T) {
	curve := curves.ED25519()
	n := 256
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.Random(crand.Reader)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	proofGenerators := RangeProofGenerators{
		g: g,
		h: h,
		u: u,
	}
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
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
