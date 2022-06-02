package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeVerifyHappyPath(t *testing.T) {
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

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeVerifyNotInRange(t *testing.T) {
	curve := curves.ED25519()
	n := 2
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
	_, err = prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.Error(t, err)
}

func TestRangeVerifyNonRandom(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.One()
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

	verifier, err := NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := getcapV(v, gamma, g, h)
	verified, err := verifier.Verify(proof, capV, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}
