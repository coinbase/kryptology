package bulletproof

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// InnerProductVerifier is the struct used to verify inner product proofs
// It specifies which curve to use and holds precomputed generators
// See NewInnerProductProver() for prover initialization
type InnerProductVerifier struct {
	curve      curves.Curve
	generators ippGenerators
}

// NewInnerProductVerifier initializes a new verifier
// It uses the specified domain to generate generators for vectors of at most maxVectorLength
// A verifier can be used to verify inner product proofs for vectors of length less than or equal to maxVectorLength
// A verifier is defined by an explicit curve
func NewInnerProductVerifier(maxVectorLength int, domain []byte, curve curves.Curve) (*InnerProductVerifier, error) {
	generators, err := getGeneratorPoints(maxVectorLength, domain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "ipp getGenerators")
	}
	return &InnerProductVerifier{curve: curve, generators: *generators}, nil
}

// Verify verifies the given proof inputs
// It implements the final comparison of section 3.1 on pg17 of https://eprint.iacr.org/2017/1066.pdf
func (verifier *InnerProductVerifier) Verify(capP, u curves.Point, proof *InnerProductProof, transcript *merlin.Transcript) (bool, error) {
	if len(proof.capLs) != len(proof.capRs) {
		return false, errors.New("ipp capLs and capRs must be same length")
	}
	// Generator vectors must be same length
	if len(verifier.generators.G) != len(verifier.generators.H) {
		return false, errors.New("ipp generator lengths of g and h must be equal")
	}

	// Get generators for each elem in a, b and one more for u
	// len(Ls) = log n, therefore can just exponentiate
	n := 1 << len(proof.capLs)

	// Length of vectors must be less than the number of generators generated
	if n > len(verifier.generators.G) {
		return false, errors.New("ipp vector length must be less than maxVectorLength")
	}
	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := verifier.generators.G[0:n]
	proofH := verifier.generators.H[0:n]

	xs, err := getxs(transcript, proof.capLs, proof.capRs, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "verifier getxs")
	}
	s, err := verifier.getsNew(xs, n)
	if err != nil {
		return false, errors.Wrap(err, "verifier getss")
	}
	lhs, err := verifier.getLHS(u, proof, proofG, proofH, s)
	if err != nil {
		return false, errors.Wrap(err, "verify getLHS")
	}
	rhs, err := verifier.getRHS(capP, proof, xs)
	if err != nil {
		return false, errors.Wrap(err, "verify getRHS")
	}
	return lhs.Equal(rhs), nil
}

// Verify verifies the given proof inputs
// It implements the final comparison of section 3.1 on pg17 of https://eprint.iacr.org/2017/1066.pdf
func (verifier *InnerProductVerifier) VerifyFromRangeProof(proofG, proofH []curves.Point, capPhmuinv, u curves.Point, tHat curves.Scalar, proof *InnerProductProof, transcript *merlin.Transcript) (bool, error) {
	// Get generators for each elem in a, b and one more for u
	// len(Ls) = log n, therefore can just exponentiate
	n := 1 << len(proof.capLs)

	xs, err := getxs(transcript, proof.capLs, proof.capRs, verifier.curve)
	if err != nil {
		return false, errors.Wrap(err, "verifier getxs")
	}
	s, err := verifier.gets(xs, n)
	if err != nil {
		return false, errors.Wrap(err, "verifier getss")
	}
	lhs, err := verifier.getLHS(u, proof, proofG, proofH, s)
	if err != nil {
		return false, errors.Wrap(err, "verify getLHS")
	}
	utHat := u.Mul(tHat)
	capP := capPhmuinv.Add(utHat)
	rhs, err := verifier.getRHS(capP, proof, xs)
	if err != nil {
		return false, errors.Wrap(err, "verify getRHS")
	}
	return lhs.Equal(rhs), nil
}

// getRHS gets the right hand side of the final comparison of section 3.1 on pg17
func (verifier *InnerProductVerifier) getRHS(P curves.Point, proof *InnerProductProof, xs []curves.Scalar) (curves.Point, error) {
	product := P
	for j, Lj := range proof.capLs {
		Rj := proof.capRs[j]
		xj := xs[j]
		xjSquare := xj.Square()
		xjSquareInv, err := xjSquare.Invert()
		if err != nil {
			return nil, errors.Wrap(err, "verify invert")
		}
		LjxjSquare := Lj.Mul(xjSquare)
		RjxjSquareInv := Rj.Mul(xjSquareInv)
		product = product.Add(LjxjSquare).Add(RjxjSquareInv)
	}
	return product, nil
}

// getLHS gets the left hand side of the final comparison of section 3.1 on pg17
func (verifier *InnerProductVerifier) getLHS(u curves.Point, proof *InnerProductProof, g, h []curves.Point, s []curves.Scalar) (curves.Point, error) {
	sInv, err := invertScalars(s)
	if err != nil {
		return nil, errors.Wrap(err, "verify invertScalars")
	}
	// g^(a*s)
	as := multiplyScalarToScalarVector(proof.a, s)
	gas := verifier.curve.Point.SumOfProducts(g, as)
	// h^(b*s^-1)
	bsInv := multiplyScalarToScalarVector(proof.b, sInv)
	hbsInv := verifier.curve.Point.SumOfProducts(h, bsInv)
	// u^a*b
	ab := proof.a.Mul(proof.b)
	uab := u.Mul(ab)
	// g^(a*s) * h^(b*s^-1) * u^a*b
	out := gas.Add(hbsInv).Add(uab)

	return out, nil
}

// getxs calculates the x values from Ls and Rs
// Note that each x is read from the transcript, then the L and R at a certain index are written to the transcript
// This mirrors the reading of xs and writing of Ls and Rs in the prover
func getxs(transcript *merlin.Transcript, Ls, Rs []curves.Point, curve curves.Curve) ([]curves.Scalar, error) {
	xs := make([]curves.Scalar, len(Ls))
	for i, Li := range Ls {
		Ri := Rs[i]
		// Add the newest L and R values to transcript
		transcript.AppendMessage([]byte("addRecursiveL"), Li.ToAffineUncompressed())
		transcript.AppendMessage([]byte("addRecursiveR"), Ri.ToAffineUncompressed())
		// Read 64 bytes from, set to scalar
		outBytes := transcript.ExtractBytes([]byte("getx"), 64)
		x, err := curve.NewScalar().SetBytesWide(outBytes)
		if err != nil {
			return nil, errors.Wrap(err, "calcx NewScalar SetBytesWide")
		}
		xs[i] = x
	}

	return xs, nil
}

// gets calculates the vector s of values used for verification
// See the second expression of section 3.1 on pg15
//nolint
func (verifier *InnerProductVerifier) gets(xs []curves.Scalar, n int) ([]curves.Scalar, error) {
	ss := make([]curves.Scalar, n)
	for i := 0; i < n; i++ {
		si := verifier.curve.Scalar.One()
		for j, xj := range xs {
			if i>>(len(xs)-j-1)&0x01 == 1 {
				si = si.Mul(xj)
			} else {
				xjInverse, err := xj.Invert()
				if err != nil {
					return nil, errors.Wrap(err, "getss invert")
				}
				si = si.Mul(xjInverse)
			}
		}
		ss[i] = si
	}

	return ss, nil
}

// getsNew calculates the vector s of values used for verification
// It provides analogous functionality as gets(), but uses a O(n) algorithm vs O(nlogn)
// The algorithm inverts all xs, then begins multiplying the inversion by the square of x elements to
// calculate all s values thus minimizing necessary inversions/ computation
func (verifier *InnerProductVerifier) getsNew(xs []curves.Scalar, n int) ([]curves.Scalar, error) {
	var err error
	ss := make([]curves.Scalar, n)
	// First element is all xs inverted mul'd
	ss[0] = verifier.curve.Scalar.One()
	for _, xj := range xs {
		ss[0] = ss[0].Mul(xj)
	}
	ss[0], err = ss[0].Invert()
	if err != nil {
		return nil, errors.Wrap(err, "ipp gets inv ss0")
	}
	for j, xj := range xs {
		xjSquared := xj.Square()
		for i := 0; i < n; i += 1 << (len(xs) - j) {
			ss[i+1<<(len(xs)-j-1)] = ss[i].Mul(xjSquared)
		}
	}

	return ss, nil
}
