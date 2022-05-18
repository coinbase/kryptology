package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeBatchVerifyHappyPath(t *testing.T) {
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

	verifier, err := NewRangeVerifier(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapVBatched(v, gamma, g, h)
	verified, err := verifier.VerifyBatched(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeBatchVerifyNotInRange(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v1 := curve.Scalar.One()
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
	_, err = prover.BatchProve(v, gamma, n, proofGenerators, transcript)
	require.Error(t, err)
}

func TestRangeBatchVerifyNonRandom(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v1 := curve.Scalar.One()
	v2 := curve.Scalar.One()
	v3 := curve.Scalar.One()
	v4 := curve.Scalar.One()
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

	verifier, err := NewRangeVerifier(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapVBatched(v, gamma, g, h)
	verified, err := verifier.VerifyBatched(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeBatchVerifyInvalid(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v1 := curve.Scalar.One()
	v2 := curve.Scalar.One()
	v3 := curve.Scalar.One()
	v4 := curve.Scalar.One()
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

	verifier, err := NewRangeVerifier(n*4, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapVBatched(v, gamma, g, h)
	capV[0] = curve.Point.Random(crand.Reader)
	verified, err := verifier.VerifyBatched(proof, capV, proofGenerators, n, transcriptVerifier)
	require.Error(t, err)
	require.False(t, verified)
}
