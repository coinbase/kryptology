package bulletproof

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// VerifyBatched verifies a given batched range proof.
// It takes in a list of commitments to the secret values as capV instead of a single commitment to a single point
// when compared to the unbatched single range proof case.
func (verifier *RangeVerifier) VerifyBatched(proof *RangeProof, capV []curves.Point, proofGenerators RangeProofGenerators, n int, transcript *merlin.Transcript) (bool, error) {
	// Define nm as the total bits required for secrets, calculated as number of secrets * n
	m := len(capV)
	nm := n * m
	// nm must be less than the number of generators generated
	if nm > len(verifier.generators.G) {
		return false, errors.New("ipp vector length must be less than maxVectorLength")
	}

	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := verifier.generators.G[0:nm]
	proofH := verifier.generators.H[0:nm]

	// Calc y,z,x from Fiat Shamir heuristic
	y, z, err := calcyzBatched(capV, proof.capA, proof.capS, transcript, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	x, err := calcx(proof.capT1, proof.capT2, transcript, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	wBytes := transcript.ExtractBytes([]byte("getw"), 64)
	w, err := verifier.curve.NewScalar().SetBytesWide(wBytes)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof prove")
	}

	// Calc delta(y,z), redefined for batched case on pg21
	deltayzBatched, err := deltayzBatched(y, z, n, m, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	// Check tHat: L65, pg20
	// See equation 72 on pg21
	tHatIsValid := verifier.checktHatBatched(proof, capV, proofGenerators.g, proofGenerators.h, deltayzBatched, x, z, m)
	if !tHatIsValid {
		return false, errors.New("rangeproof verify tHat is invalid")
	}

	// Verify IPP
	hPrime, err := gethPrime(proofH, y, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	capPhmu := getPhmuBatched(proofG, hPrime, proofGenerators.h, proof.capA, proof.capS, x, y, z, proof.mu, n, m, verifier.curve)

	ippVerified, err := verifier.ippVerifier.VerifyFromRangeProof(proofG, hPrime, capPhmu, proofGenerators.u.Mul(w), proof.tHat, proof.ipp, transcript)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	return ippVerified, nil
}

// L65, pg20.
func (verifier *RangeVerifier) checktHatBatched(proof *RangeProof, capV []curves.Point, g, h curves.Point, deltayz, x, z curves.Scalar, m int) bool {
	// g^tHat * h^tau_x
	gtHat := g.Mul(proof.tHat)
	htaux := h.Mul(proof.taux)
	lhs := gtHat.Add(htaux)

	// V^z^2 * g^delta(y,z) * Tau_1^x * Tau_2^x^2
	// g^delta(y,z) * V^(z^2*z^m) * Tau_1^x * Tau_2^x^2
	zm := getknVector(z, m, verifier.curve)
	zsquarezm := multiplyScalarToScalarVector(z.Square(), zm)
	capVzsquaretwom := verifier.curve.Point.SumOfProducts(capV, zsquarezm)
	gdeltayz := g.Mul(deltayz)
	capTau1x := proof.capT1.Mul(x)
	capTau2xsquare := proof.capT2.Mul(x.Square())
	rhs := capVzsquaretwom.Add(gdeltayz).Add(capTau1x).Add(capTau2xsquare)

	// Compare lhs =? rhs
	return lhs.Equal(rhs)
}
