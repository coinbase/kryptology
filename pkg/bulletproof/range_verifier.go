package bulletproof

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// RangeVerifier is the struct used to verify RangeProofs
// It specifies which curve to use and holds precomputed generators
// See NewRangeVerifier() for verifier initialization
type RangeVerifier struct {
	curve       curves.Curve
	generators  *ippGenerators
	ippVerifier *InnerProductVerifier
}

// NewRangeVerifier initializes a new verifier
// It uses the specified domain to generate generators for vectors of at most maxVectorLength
// A verifier can be used to verify range proofs for vectors of length less than or equal to maxVectorLength
// A verifier is defined by an explicit curve
func NewRangeVerifier(maxVectorLength int, rangeDomain, ippDomain []byte, curve curves.Curve) (*RangeVerifier, error) {
	generators, err := getGeneratorPoints(maxVectorLength, rangeDomain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "range NewRangeProver")
	}
	ippVerifier, err := NewInnerProductVerifier(maxVectorLength, ippDomain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "range NewRangeProver")
	}
	return &RangeVerifier{curve: curve, generators: generators, ippVerifier: ippVerifier}, nil
}

// Verify verifies the given range proof inputs
// It implements the checking of L65 on pg 20
// It also verifies the dot product of <l,r> using the inner product proof\
// capV is a commitment to v using blinding factor gamma
// n is the power that specifies the upper bound of the range, ie. 2^n
// g, h, u are unique points used as generators for the blinding factor
// transcript is a merlin transcript to be used for the fiat shamir heuristic
func (verifier *RangeVerifier) Verify(proof *RangeProof, capV, g, h, u curves.Point, n int, transcript *merlin.Transcript) (bool, error) {
	// Length of vectors must be less than the number of generators generated
	if n > len(verifier.generators.G) {
		return false, errors.New("ipp vector length must be less than maxVectorLength")
	}
	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := verifier.generators.G[0:n]
	proofH := verifier.generators.H[0:n]

	// Calc y,z,x from Fiat Shamir heuristic
	y, z, err := calcyz(capV, proof.capA, proof.capS, transcript, verifier.curve)
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

	// Calc delta(y,z)
	deltayz, err := deltayz(y, z, n, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	// Check tHat: L65, pg20
	tHatIsValid := verifier.checktHat(proof, capV, g, h, deltayz, x, z)
	if !tHatIsValid {
		return false, errors.New("rangeproof verify tHat is invalid")
	}

	// Verify IPP
	hPrime, err := gethPrime(proofH, y, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	capPhmu, err := getPhmu(proofG, hPrime, h, proof.capA, proof.capS, x, y, z, proof.mu, n, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	ippVerified, err := verifier.ippVerifier.VerifyFromRangeProof(proofG, hPrime, capPhmu, u.Mul(w), proof.tHat, proof.ipp, transcript)
	if err != nil {
		return false, errors.Wrap(err, "rangeproof verify")
	}

	return ippVerified, nil
}

// L65, pg20
func (verifier *RangeVerifier) checktHat(proof *RangeProof, capV, g, h curves.Point, deltayz, x, z curves.Scalar) bool {
	// g^tHat * h^tau_x
	gtHat := g.Mul(proof.tHat)
	htaux := h.Mul(proof.taux)
	lhs := gtHat.Add(htaux)

	// V^z^2 * g^delta(y,z) * Tau_1^x * Tau_2^x^2
	capVzsquare := capV.Mul(z.Square())
	gdeltayz := g.Mul(deltayz)
	capTau1x := proof.capT1.Mul(x)
	capTau2xsquare := proof.capT2.Mul(x.Square())
	rhs := capVzsquare.Add(gdeltayz).Add(capTau1x).Add(capTau2xsquare)

	// Compare lhs =? rhs
	return lhs.Equal(rhs)
}

// gethPrime calculates new h prime generators as defined in L64 on pg20
func gethPrime(h []curves.Point, y curves.Scalar, curve curves.Curve) ([]curves.Point, error) {
	hPrime := make([]curves.Point, len(h))
	yInv, err := y.Invert()
	yInvn := getknVector(yInv, len(h), curve)
	if err != nil {
		return nil, errors.Wrap(err, "gethPrime")
	}
	for i, hElem := range h {
		hPrime[i] = hElem.Mul(yInvn[i])
	}
	return hPrime, nil
}

// Obtain P used for IPP verification
// See L67 on pg20
// Note P on L66 includes blinding factor hmu, this method removes that factor
func getPhmu(proofG, proofHPrime []curves.Point, h, capA, capS curves.Point, x, y, z, mu curves.Scalar, n int, curve curves.Curve) (curves.Point, error) {
	// h'^(z*y^n + z^2*2^n)
	zyn := multiplyScalarToScalarVector(z, getknVector(y, n, curve))
	zsquaretwon := multiplyScalarToScalarVector(z.Square(), get2nVector(n, curve))
	elemLastExponent, err := addPairwiseScalarVectors(zyn, zsquaretwon)
	if err != nil {
		return nil, errors.Wrap(err, "getPhmu")
	}
	lastElem := curve.Point.SumOfProducts(proofHPrime, elemLastExponent)

	// S^x
	capSx := capS.Mul(x)

	// g^-z --> -z*<1,g>
	onen := get1nVector(n, curve)
	zNeg := z.Neg()
	if err != nil {
		return nil, errors.Wrap(err, "getPhmu")
	}
	zinvonen := multiplyScalarToScalarVector(zNeg, onen)
	zgdotonen := curve.Point.SumOfProducts(proofG, zinvonen)

	// L66 on pg20
	P := capA.Add(capSx).Add(zgdotonen).Add(lastElem)
	hmu := h.Mul(mu)
	Phmu := P.Sub(hmu)

	return Phmu, nil
}

// Delta function for delta(y,z), See (39) on pg18
func deltayz(y, z curves.Scalar, n int, curve curves.Curve) (curves.Scalar, error) {
	// z - z^2
	zMinuszsquare := z.Sub(z.Square())
	// 1^n
	onen := get1nVector(n, curve)
	// <1^n, y^n>
	onendotyn, err := innerProduct(onen, getknVector(y, n, curve))
	if err != nil {
		return nil, errors.Wrap(err, "deltayz")
	}
	// (z - z^2)*<1^n, y^n>
	termFirst := zMinuszsquare.Mul(onendotyn)

	// <1^n, 2^n>
	onendottwon, err := innerProduct(onen, get2nVector(n, curve))
	if err != nil {
		return nil, errors.Wrap(err, "deltayz")
	}
	// z^3*<1^n, 2^n>
	termSecond := z.Cube().Mul(onendottwon)

	// (z - z^2)*<1^n, y^n> - z^3*<1^n, 2^n>
	out := termFirst.Sub(termSecond)

	return out, nil
}
