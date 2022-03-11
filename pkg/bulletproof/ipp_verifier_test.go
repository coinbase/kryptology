package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestIPPVerifyHappyPath(t *testing.T) {
	curve := curves.ED25519()
	vecLength := 256
	prover, err := NewInnerProductProver(vecLength, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(vecLength, *curve)
	b := randScalarVec(vecLength, *curve)
	u := curve.Point.Random(crand.Reader)
	transcriptProver := merlin.NewTranscript("test")
	proof, err := prover.Prove(a, b, u, transcriptProver)
	require.NoError(t, err)

	verifier, err := NewInnerProductVerifier(vecLength, []byte("test"), *curve)
	require.NoError(t, err)
	capP, err := prover.getP(a, b, u)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	verified, err := verifier.Verify(capP, u, proof, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)
}

func BenchmarkIPPVerification(bench *testing.B) {
	curve := curves.ED25519()
	vecLength := 1024
	prover, _ := NewInnerProductProver(vecLength, []byte("test"), *curve)
	a := randScalarVec(vecLength, *curve)
	b := randScalarVec(vecLength, *curve)
	u := curve.Point.Random(crand.Reader)
	transcriptProver := merlin.NewTranscript("test")
	proof, _ := prover.Prove(a, b, u, transcriptProver)

	verifier, _ := NewInnerProductVerifier(vecLength, []byte("test"), *curve)
	capP, _ := prover.getP(a, b, u)
	transcriptVerifier := merlin.NewTranscript("test")
	verified, _ := verifier.Verify(capP, u, proof, transcriptVerifier)
	require.True(bench, verified)
}

func TestIPPVerifyInvalidProof(t *testing.T) {
	curve := curves.ED25519()
	vecLength := 64
	prover, err := NewInnerProductProver(vecLength, []byte("test"), *curve)
	require.NoError(t, err)

	a := randScalarVec(vecLength, *curve)
	b := randScalarVec(vecLength, *curve)
	u := curve.Point.Random(crand.Reader)

	aPrime := randScalarVec(64, *curve)
	bPrime := randScalarVec(64, *curve)
	uPrime := curve.Point.Random(crand.Reader)
	transcriptProver := merlin.NewTranscript("test")

	proofPrime, err := prover.Prove(aPrime, bPrime, uPrime, transcriptProver)
	require.NoError(t, err)

	verifier, err := NewInnerProductVerifier(vecLength, []byte("test"), *curve)
	require.NoError(t, err)
	capP, err := prover.getP(a, b, u)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	// Check for different capP, u from proof
	verified, err := verifier.Verify(capP, u, proofPrime, transcriptVerifier)
	require.NoError(t, err)
	require.False(t, verified)
}
