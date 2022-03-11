package bulletproof

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestIPPHappyPath(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(8, *curve)
	b := randScalarVec(8, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(a, b, u, transcript)
	require.NoError(t, err)
	require.Equal(t, 3, len(proof.capLs))
	require.Equal(t, 3, len(proof.capRs))
}

func TestIPPMismatchedVectors(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(4, *curve)
	b := randScalarVec(8, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(a, b, u, transcript)
	require.Error(t, err)
}

func TestIPPNonPowerOfTwoLengthVectors(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(3, *curve)
	b := randScalarVec(3, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(a, b, u, transcript)
	require.Error(t, err)
}

func TestIPPZeroLengthVectors(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(0, *curve)
	b := randScalarVec(0, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(a, b, u, transcript)
	require.Error(t, err)
}

func TestIPPGreaterThanMaxLengthVectors(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(16, *curve)
	b := randScalarVec(16, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(a, b, u, transcript)
	require.Error(t, err)
}

func TestIPPMarshal(t *testing.T) {
	curve := curves.ED25519()
	prover, err := NewInnerProductProver(8, []byte("test"), *curve)
	require.NoError(t, err)
	a := randScalarVec(8, *curve)
	b := randScalarVec(8, *curve)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(a, b, u, transcript)
	require.NoError(t, err)

	proofMarshaled := proof.MarshalBinary()
	proofPrime := NewInnerProductProof(curve)
	err = proofPrime.UnmarshalBinary(proofMarshaled)
	require.NoError(t, err)
	require.Zero(t, proof.a.Cmp(proofPrime.a))
	require.Zero(t, proof.b.Cmp(proofPrime.b))
	for i, proofCapLElem := range proof.capLs {
		proofPrimeCapLElem := proofPrime.capLs[i]
		require.True(t, proofCapLElem.Equal(proofPrimeCapLElem))
		proofCapRElem := proof.capRs[i]
		proofPrimeCapRElem := proofPrime.capRs[i]
		require.True(t, proofCapRElem.Equal(proofPrimeCapRElem))
	}
}
