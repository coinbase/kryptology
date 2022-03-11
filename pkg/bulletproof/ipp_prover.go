//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package bulletproof implements the zero knowledge protocol bulletproofs as defined in https://eprint.iacr.org/2017/1066.pdf
package bulletproof

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// InnerProductProver is the struct used to create InnerProductProofs
// It specifies which curve to use and holds precomputed generators
// See NewInnerProductProver() for prover initialization
type InnerProductProver struct {
	curve      curves.Curve
	generators ippGenerators
}

// InnerProductProof contains necessary output for the inner product proof
// a and b are the final input vectors of scalars, they should be of length 1
// Ls and Rs are calculated per recursion of the IPP and are necessary for verification
// See section 3.1 on pg 15 of https://eprint.iacr.org/2017/1066.pdf
type InnerProductProof struct {
	a, b         curves.Scalar
	capLs, capRs []curves.Point
	curve        *curves.Curve
}

// ippRecursion is the same as IPP but tracks recursive a', b', g', h' and Ls and Rs
// It should only be used internally by InnerProductProver.Prove()
// See L35 on pg 16 of https://eprint.iacr.org/2017/1066.pdf
type ippRecursion struct {
	a, b         []curves.Scalar
	c            curves.Scalar
	capLs, capRs []curves.Point
	g, h         []curves.Point
	u, capP      curves.Point
	transcript   *merlin.Transcript
}

// NewInnerProductProver initializes a new prover
// It uses the specified domain to generate generators for vectors of at most maxVectorLength
// A prover can be used to construct inner product proofs for vectors of length less than or equal to maxVectorLength
// A prover is defined by an explicit curve
func NewInnerProductProver(maxVectorLength int, domain []byte, curve curves.Curve) (*InnerProductProver, error) {
	generators, err := getGeneratorPoints(maxVectorLength, domain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "ipp getGenerators")
	}
	return &InnerProductProver{curve: curve, generators: *generators}, nil
}

// NewInnerProductProof initializes a new InnerProductProof for a specified curve
// This should be used in tandem with UnmarshalBinary() to convert a marshaled proof into the struct
func NewInnerProductProof(curve *curves.Curve) *InnerProductProof {
	var capLs, capRs []curves.Point
	newProof := InnerProductProof{
		a:     curve.NewScalar(),
		b:     curve.NewScalar(),
		capLs: capLs,
		capRs: capRs,
		curve: curve,
	}
	return &newProof
}

// rangeToIPP takes the output of a range proof and converts it into an inner product proof
// See section 4.2 on pg 20
// The conversion specifies generators to use (g and hPrime), as well as the two vectors l, r of which the inner product is tHat
// Additionally, note that the P used for the IPP is in fact P*h^-mu from the range proof
func (prover *InnerProductProver) rangeToIPP(proofG, proofH []curves.Point, l, r []curves.Scalar, tHat curves.Scalar, capPhmuinv, u curves.Point, transcript *merlin.Transcript) (*InnerProductProof, error) {
	// Note that P as a witness is only g^l * h^r
	// P needs to be in the form of g^l * h^r * u^<l,r>
	// Calculate the final P including the u^<l,r> term
	utHat := u.Mul(tHat)
	capP := capPhmuinv.Add(utHat)

	// Use params to prove inner product
	recursionParams := &ippRecursion{
		a:          l,
		b:          r,
		capLs:      []curves.Point{},
		capRs:      []curves.Point{},
		c:          tHat,
		g:          proofG,
		h:          proofH,
		capP:       capP,
		u:          u,
		transcript: transcript,
	}

	return prover.proveRecursive(recursionParams)
}

// getP returns the initial P value given two scalars a,b and point u
// This method should only be used for testing
// See (3) on page 13 of https://eprint.iacr.org/2017/1066.pdf
func (prover *InnerProductProver) getP(a, b []curves.Scalar, u curves.Point) (curves.Point, error) {
	// Vectors must have length power of two
	if !isPowerOfTwo(len(a)) {
		return nil, errors.New("ipp vector length must be power of two")
	}
	// Generator vectors must be same length
	if len(prover.generators.G) != len(prover.generators.H) {
		return nil, errors.New("ipp generator lengths of g and h must be equal")
	}
	// Inner product requires len(a) == len(b) else error is returned
	c, err := innerProduct(a, b)
	if err != nil {
		return nil, errors.Wrap(err, "ipp getInnerProduct")
	}

	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := prover.generators.G[0:len(a)]
	proofH := prover.generators.H[0:len(b)]

	// initial P = g^a * h^b * u^(a dot b) (See (3) on page 13 of https://eprint.iacr.org/2017/1066.pdf)
	ga := prover.curve.NewGeneratorPoint().SumOfProducts(proofG, a)
	hb := prover.curve.NewGeneratorPoint().SumOfProducts(proofH, b)
	uadotb := u.Mul(c)
	capP := ga.Add(hb).Add(uadotb)

	return capP, nil
}

// Prove executes the prover protocol on pg 16 of https://eprint.iacr.org/2017/1066.pdf
// It generates an inner product proof for vectors a and b, using u to blind the inner product in P
// A transcript is used for the Fiat Shamir heuristic
func (prover *InnerProductProver) Prove(a, b []curves.Scalar, u curves.Point, transcript *merlin.Transcript) (*InnerProductProof, error) {
	// Vectors must have length power of two
	if !isPowerOfTwo(len(a)) {
		return nil, errors.New("ipp vector length must be power of two")
	}
	// Generator vectors must be same length
	if len(prover.generators.G) != len(prover.generators.H) {
		return nil, errors.New("ipp generator lengths of g and h must be equal")
	}
	// Inner product requires len(a) == len(b) else error is returned
	c, err := innerProduct(a, b)
	if err != nil {
		return nil, errors.Wrap(err, "ipp getInnerProduct")
	}

	// Length of vectors must be less than the number of generators generated
	if len(a) > len(prover.generators.G) {
		return nil, errors.New("ipp vector length must be less than maxVectorLength")
	}
	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := prover.generators.G[0:len(a)]
	proofH := prover.generators.H[0:len(b)]

	// initial P = g^a * h^b * u^(a dot b) (See (3) on page 13 of https://eprint.iacr.org/2017/1066.pdf)
	ga := prover.curve.NewGeneratorPoint().SumOfProducts(proofG, a)
	hb := prover.curve.NewGeneratorPoint().SumOfProducts(proofH, b)
	uadotb := u.Mul(c)
	capP := ga.Add(hb).Add(uadotb)

	recursionParams := &ippRecursion{
		a:          a,
		b:          b,
		capLs:      []curves.Point{},
		capRs:      []curves.Point{},
		c:          c,
		g:          proofG,
		h:          proofH,
		capP:       capP,
		u:          u,
		transcript: transcript,
	}
	return prover.proveRecursive(recursionParams)
}

// proveRecursive executes the recursion on pg 16 of https://eprint.iacr.org/2017/1066.pdf
func (prover *InnerProductProver) proveRecursive(recursionParams *ippRecursion) (*InnerProductProof, error) {
	// length checks
	if len(recursionParams.a) != len(recursionParams.b) {
		return nil, errors.New("ipp proveRecursive a and b different lengths")
	}
	if len(recursionParams.g) != len(recursionParams.h) {
		return nil, errors.New("ipp proveRecursive g and h different lengths")
	}
	if len(recursionParams.a) != len(recursionParams.g) {
		return nil, errors.New("ipp proveRecursive scalar and point vectors different lengths")
	}
	// Base case (L14, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	if len(recursionParams.a) == 1 {
		proof := &InnerProductProof{
			a:     recursionParams.a[0],
			b:     recursionParams.b[0],
			capLs: recursionParams.capLs,
			capRs: recursionParams.capRs,
			curve: &prover.curve,
		}
		return proof, nil
	}

	// Split current state into low (first half) vs high (second half) vectors
	aLo, aHi, err := splitScalarVector(recursionParams.a)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams splitScalarVector")
	}
	bLo, bHi, err := splitScalarVector(recursionParams.b)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams splitScalarVector")
	}
	gLo, gHi, err := splitPointVector(recursionParams.g)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams splitPointVector")
	}
	hLo, hHi, err := splitPointVector(recursionParams.h)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams splitPointVector")
	}

	// c_l, c_r (L21,22, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	cL, err := innerProduct(aLo, bHi)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams innerProduct")
	}

	cR, err := innerProduct(aHi, bLo)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams innerProduct")
	}

	// L, R (L23,24, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	lga := prover.curve.Point.SumOfProducts(gHi, aLo)
	lhb := prover.curve.Point.SumOfProducts(hLo, bHi)
	ucL := recursionParams.u.Mul(cL)
	capL := lga.Add(lhb).Add(ucL)

	rga := prover.curve.Point.SumOfProducts(gLo, aHi)
	rhb := prover.curve.Point.SumOfProducts(hHi, bLo)
	ucR := recursionParams.u.Mul(cR)
	capR := rga.Add(rhb).Add(ucR)

	// Add L,R for verifier to use to calculate final g, h
	newL := append(recursionParams.capLs, capL)
	newR := append(recursionParams.capRs, capR)

	// Get x from L, R for non-interactive (See section 4.4 pg22 of https://eprint.iacr.org/2017/1066.pdf)
	// Note this replaces the interactive model, i.e. L36-28 of pg16 of https://eprint.iacr.org/2017/1066.pdf
	x, err := prover.calcx(capL, capR, recursionParams.transcript)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams calcx")
	}

	// Calculate recursive inputs
	xInv, err := x.Invert()
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams x.Invert")
	}

	// g', h' (L29,30, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	gLoxInverse := multiplyScalarToPointVector(xInv, gLo)
	gHix := multiplyScalarToPointVector(x, gHi)
	gPrime, err := multiplyPairwisePointVectors(gLoxInverse, gHix)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams multiplyPairwisePointVectors")
	}

	hLox := multiplyScalarToPointVector(x, hLo)
	hHixInv := multiplyScalarToPointVector(xInv, hHi)
	hPrime, err := multiplyPairwisePointVectors(hLox, hHixInv)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams multiplyPairwisePointVectors")
	}

	// P' (L31, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	xSquare := x.Square()
	xInvSquare := xInv.Square()
	LxSquare := capL.Mul(xSquare)
	RxInvSquare := capR.Mul(xInvSquare)
	PPrime := LxSquare.Add(recursionParams.capP).Add(RxInvSquare)

	// a', b' (L33, 34, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	aLox := multiplyScalarToScalarVector(x, aLo)
	aHixIn := multiplyScalarToScalarVector(xInv, aHi)
	aPrime, err := addPairwiseScalarVectors(aLox, aHixIn)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams addPairwiseScalarVectors")
	}

	bLoxInv := multiplyScalarToScalarVector(xInv, bLo)
	bHix := multiplyScalarToScalarVector(x, bHi)
	bPrime, err := addPairwiseScalarVectors(bLoxInv, bHix)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams addPairwiseScalarVectors")
	}

	// c'
	cPrime, err := innerProduct(aPrime, bPrime)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams innerProduct")
	}

	// Make recursive call (L35, pg16 of https://eprint.iacr.org/2017/1066.pdf)
	recursiveIPP := &ippRecursion{
		a:          aPrime,
		b:          bPrime,
		capLs:      newL,
		capRs:      newR,
		c:          cPrime,
		g:          gPrime,
		h:          hPrime,
		capP:       PPrime,
		u:          recursionParams.u,
		transcript: recursionParams.transcript,
	}

	out, err := prover.proveRecursive(recursiveIPP)
	if err != nil {
		return nil, errors.Wrap(err, "recursionParams proveRecursive")
	}
	return out, nil
}

// calcx uses a merlin transcript for Fiat Shamir
// For each recursion, it takes the current state of the transcript and appends the newly calculated L and R values
// A new scalar is then read from the transcript
// See section 4.4 pg22 of https://eprint.iacr.org/2017/1066.pdf
func (prover *InnerProductProver) calcx(L, R curves.Point, transcript *merlin.Transcript) (curves.Scalar, error) {
	// Add the newest L and R values to transcript
	transcript.AppendMessage([]byte("addRecursiveL"), L.ToAffineUncompressed())
	transcript.AppendMessage([]byte("addRecursiveR"), R.ToAffineUncompressed())
	// Read 64 bytes from, set to scalar
	outBytes := transcript.ExtractBytes([]byte("getx"), 64)
	x, err := prover.curve.NewScalar().SetBytesWide(outBytes)
	if err != nil {
		return nil, errors.Wrap(err, "calcx NewScalar SetBytesWide")
	}

	return x, nil
}

// MarshalBinary takes an inner product proof and marshals into bytes
func (proof *InnerProductProof) MarshalBinary() []byte {
	var out []byte
	out = append(out, proof.a.Bytes()...)
	out = append(out, proof.b.Bytes()...)
	for i, capLElem := range proof.capLs {
		capRElem := proof.capRs[i]
		out = append(out, capLElem.ToAffineCompressed()...)
		out = append(out, capRElem.ToAffineCompressed()...)
	}
	return out
}

// UnmarshalBinary takes bytes of a marshaled proof and writes them into an inner product proof
// The inner product proof used should be from the output of NewInnerProductProof()
func (proof *InnerProductProof) UnmarshalBinary(data []byte) error {
	scalarLen := len(proof.curve.NewScalar().Bytes())
	pointLen := len(proof.curve.NewGeneratorPoint().ToAffineCompressed())
	ptr := 0
	// Get scalars
	a, err := proof.curve.NewScalar().SetBytes(data[ptr : ptr+scalarLen])
	if err != nil {
		return errors.New("InnerProductProof UnmarshalBinary SetBytes")
	}
	proof.a = a
	ptr += scalarLen
	b, err := proof.curve.NewScalar().SetBytes(data[ptr : ptr+scalarLen])
	if err != nil {
		return errors.New("InnerProductProof UnmarshalBinary SetBytes")
	}
	proof.b = b
	ptr += scalarLen
	// Get points
	var capLs, capRs []curves.Point
	for ptr < len(data) {
		capLElem, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
		if err != nil {
			return errors.New("InnerProductProof UnmarshalBinary FromAffineCompressed")
		}
		capLs = append(capLs, capLElem)
		ptr += pointLen
		capRElem, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
		if err != nil {
			return errors.New("InnerProductProof UnmarshalBinary FromAffineCompressed")
		}
		capRs = append(capRs, capRElem)
		ptr += pointLen
	}
	proof.capLs = capLs
	proof.capRs = capRs

	return nil
}
