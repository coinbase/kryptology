//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package bulletproof implements the zero knowledge protocol bulletproofs as defined in https://eprint.iacr.org/2017/1066.pdf
package bulletproof

import (
	crand "crypto/rand"
	"math/big"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// RangeProver is the struct used to create RangeProofs
// It specifies which curve to use and holds precomputed generators
// See NewRangeProver() for prover initialization.
type RangeProver struct {
	curve      curves.Curve
	generators *ippGenerators
	ippProver  *InnerProductProver
}

// RangeProof is the struct used to hold a range proof
// capA is a commitment to a_L and a_R using randomness alpha
// capS is a commitment to s_L and s_R using randomness rho
// capTau1,2 are commitments to t1,t2 respectively using randomness tau_1,2
// tHat represents t(X) as defined on page 19
// taux is the blinding factor for tHat
// ipp is the inner product proof used for compacting the transfer of l,r (See 4.2 on pg20).
type RangeProof struct {
	capA, capS, capT1, capT2 curves.Point
	taux, mu, tHat           curves.Scalar
	ipp                      *InnerProductProof
	curve                    *curves.Curve
}

type RangeProofGenerators struct {
	g, h, u curves.Point
}

// NewRangeProver initializes a new prover
// It uses the specified domain to generate generators for vectors of at most maxVectorLength
// A prover can be used to construct range proofs for vectors of length less than or equal to maxVectorLength
// A prover is defined by an explicit curve.
func NewRangeProver(maxVectorLength int, rangeDomain, ippDomain []byte, curve curves.Curve) (*RangeProver, error) {
	generators, err := getGeneratorPoints(maxVectorLength, rangeDomain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "range NewRangeProver")
	}
	ippProver, err := NewInnerProductProver(maxVectorLength, ippDomain, curve)
	if err != nil {
		return nil, errors.Wrap(err, "range NewRangeProver")
	}
	return &RangeProver{curve: curve, generators: generators, ippProver: ippProver}, nil
}

// NewRangeProof initializes a new RangeProof for a specified curve
// This should be used in tandem with UnmarshalBinary() to convert a marshaled proof into the struct.
func NewRangeProof(curve *curves.Curve) *RangeProof {
	out := RangeProof{
		capA:  nil,
		capS:  nil,
		capT1: nil,
		capT2: nil,
		taux:  nil,
		mu:    nil,
		tHat:  nil,
		ipp:   NewInnerProductProof(curve),
		curve: curve,
	}

	return &out
}

// Prove uses the range prover to prove that some value v is within the range [0, 2^n]
// It implements the protocol defined on pgs 19,20 in https://eprint.iacr.org/2017/1066.pdf
// v is the value of which to prove the range
// n is the power that specifies the upper bound of the range, ie. 2^n
// gamma is a scalar used for as a blinding factor
// g, h, u are unique points used as generators for the blinding factor
// transcript is a merlin transcript to be used for the fiat shamir heuristic.
func (prover *RangeProver) Prove(v, gamma curves.Scalar, n int, proofGenerators RangeProofGenerators, transcript *merlin.Transcript) (*RangeProof, error) {
	// n must be less than or equal to the number of generators generated
	if n > len(prover.generators.G) {
		return nil, errors.New("ipp vector length must be less than or equal to maxVectorLength")
	}
	// In case where len(a) is less than number of generators precomputed by prover, trim to length
	proofG := prover.generators.G[0:n]
	proofH := prover.generators.H[0:n]

	// Check that v is in range [0, 2^n]
	if bigZero := big.NewInt(0); v.BigInt().Cmp(bigZero) == -1 {
		return nil, errors.New("v is less than 0")
	}

	bigTwo := big.NewInt(2)
	if n < 0 {
		return nil, errors.New("n cannot be less than 0")
	}
	bigN := big.NewInt(int64(n))
	var bigTwoToN big.Int
	bigTwoToN.Exp(bigTwo, bigN, nil)
	if v.BigInt().Cmp(&bigTwoToN) == 1 {
		return nil, errors.New("v is greater than 2^n")
	}

	// L40 on pg19
	aL, err := getaL(v, n, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	onen := get1nVector(n, prover.curve)
	// L41 on pg19
	aR, err := subtractPairwiseScalarVectors(aL, onen)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	alpha := prover.curve.Scalar.Random(crand.Reader)
	// Calc A (L44, pg19)
	halpha := proofGenerators.h.Mul(alpha)
	gaL := prover.curve.Point.SumOfProducts(proofG, aL)
	haR := prover.curve.Point.SumOfProducts(proofH, aR)
	capA := halpha.Add(gaL).Add(haR)

	// L45, 46, pg19
	sL := getBlindingVector(n, prover.curve)
	sR := getBlindingVector(n, prover.curve)
	rho := prover.curve.Scalar.Random(crand.Reader)

	// Calc S (L47, pg19)
	hrho := proofGenerators.h.Mul(rho)
	gsL := prover.curve.Point.SumOfProducts(proofG, sL)
	hsR := prover.curve.Point.SumOfProducts(proofH, sR)
	capS := hrho.Add(gsL).Add(hsR)

	// Fiat Shamir for y,z (L49, pg19)
	capV := getcapV(v, gamma, proofGenerators.g, proofGenerators.h)
	y, z, err := calcyz(capV, capA, capS, transcript, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc t_1, t_2
	// See the l(X), r(X), t(X) equations on pg 19
	// Use l(X)'s and r(X)'s constant and linear terms to derive t_1 and t_2
	// (a_l - z*1^n)
	zonen := multiplyScalarToScalarVector(z, onen)
	constantTerml, err := subtractPairwiseScalarVectors(aL, zonen)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	linearTerml := sL

	// z^2 * 2^N
	twoN := get2nVector(n, prover.curve)
	zSquareTwon := multiplyScalarToScalarVector(z.Square(), twoN)
	// a_r + z*1^n
	aRPluszonen, err := addPairwiseScalarVectors(aR, zonen)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	yn := getknVector(y, n, prover.curve)
	hadamard, err := multiplyPairwiseScalarVectors(yn, aRPluszonen)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	constantTermr, err := addPairwiseScalarVectors(hadamard, zSquareTwon)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	linearTermr, err := multiplyPairwiseScalarVectors(yn, sR)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// t_1 (as the linear coefficient) is the sum of the dot products of l(X)'s linear term dot r(X)'s constant term
	// and r(X)'s linear term dot l(X)'s constant term
	t1FirstTerm, err := innerProduct(linearTerml, constantTermr)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	t1SecondTerm, err := innerProduct(linearTermr, constantTerml)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	t1 := t1FirstTerm.Add(t1SecondTerm)

	// t_2 (as the quadratic coefficient) is the dot product of l(X)'s and r(X)'s linear terms
	t2, err := innerProduct(linearTerml, linearTermr)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// L52, pg20
	tau1 := prover.curve.Scalar.Random(crand.Reader)
	tau2 := prover.curve.Scalar.Random(crand.Reader)

	// T_1, T_2 (L53, pg20)
	capT1 := proofGenerators.g.Mul(t1).Add(proofGenerators.h.Mul(tau1))
	capT2 := proofGenerators.g.Mul(t2).Add(proofGenerators.h.Mul(tau2))

	// Fiat shamir for x (L55, pg20)
	x, err := calcx(capT1, capT2, transcript, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc l (L58, pg20)
	// Instead of using the expression in the line, evaluate l() at x
	sLx := multiplyScalarToScalarVector(x, linearTerml)
	l, err := addPairwiseScalarVectors(constantTerml, sLx)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc r (L59, pg20)
	// Instead of using the expression in the line, evaluate r() at x
	ynsRx := multiplyScalarToScalarVector(x, linearTermr)
	r, err := addPairwiseScalarVectors(constantTermr, ynsRx)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc t hat (L60, pg20)
	// For efficiency, instead of calculating the dot product, evaluate t() at x
	deltayz, err := deltayz(y, z, n, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	t0 := v.Mul(z.Square()).Add(deltayz)
	tLinear := t1.Mul(x)
	tQuadratic := t2.Mul(x.Square())
	tHat := t0.Add(tLinear).Add(tQuadratic)

	// Calc tau_x (L61, pg20)
	tau2xsquare := tau2.Mul(x.Square())
	tau1x := tau1.Mul(x)
	zsquaregamma := z.Square().Mul(gamma)
	taux := tau2xsquare.Add(tau1x).Add(zsquaregamma)

	// Calc mu (L62, pg20)
	mu := alpha.Add(rho.Mul(x))

	// Calc IPP (See section 4.2)
	hPrime, err := gethPrime(proofH, y, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	capPhmu, err := getPhmu(proofG, hPrime, proofGenerators.h, capA, capS, x, y, z, mu, n, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	wBytes := transcript.ExtractBytes([]byte("getw"), 64)
	w, err := prover.curve.NewScalar().SetBytesWide(wBytes)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	ipp, err := prover.ippProver.rangeToIPP(proofG, hPrime, l, r, tHat, capPhmu, proofGenerators.u.Mul(w), transcript)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	out := &RangeProof{
		capA:  capA,
		capS:  capS,
		capT1: capT1,
		capT2: capT2,
		taux:  taux,
		mu:    mu,
		tHat:  tHat,
		ipp:   ipp,
		curve: &prover.curve,
	}
	return out, nil
}

// MarshalBinary takes a range proof and marshals into bytes.
func (proof *RangeProof) MarshalBinary() []byte {
	var out []byte
	out = append(out, proof.capA.ToAffineCompressed()...)
	out = append(out, proof.capS.ToAffineCompressed()...)
	out = append(out, proof.capT1.ToAffineCompressed()...)
	out = append(out, proof.capT2.ToAffineCompressed()...)
	out = append(out, proof.taux.Bytes()...)
	out = append(out, proof.mu.Bytes()...)
	out = append(out, proof.tHat.Bytes()...)
	out = append(out, proof.ipp.MarshalBinary()...)

	return out
}

// UnmarshalBinary takes bytes of a marshaled proof and writes them into a range proof
// The range proof used should be from the output of NewRangeProof().
func (proof *RangeProof) UnmarshalBinary(data []byte) error {
	scalarLen := len(proof.curve.NewScalar().Bytes())
	pointLen := len(proof.curve.NewGeneratorPoint().ToAffineCompressed())
	ptr := 0
	// Get points
	capA, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary FromAffineCompressed")
	}
	proof.capA = capA
	ptr += pointLen
	capS, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary FromAffineCompressed")
	}
	proof.capS = capS
	ptr += pointLen
	capT1, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary FromAffineCompressed")
	}
	proof.capT1 = capT1
	ptr += pointLen
	capT2, err := proof.curve.Point.FromAffineCompressed(data[ptr : ptr+pointLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary FromAffineCompressed")
	}
	proof.capT2 = capT2
	ptr += pointLen

	// Get scalars
	taux, err := proof.curve.NewScalar().SetBytes(data[ptr : ptr+scalarLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary SetBytes")
	}
	proof.taux = taux
	ptr += scalarLen
	mu, err := proof.curve.NewScalar().SetBytes(data[ptr : ptr+scalarLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary SetBytes")
	}
	proof.mu = mu
	ptr += scalarLen
	tHat, err := proof.curve.NewScalar().SetBytes(data[ptr : ptr+scalarLen])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary SetBytes")
	}
	proof.tHat = tHat
	ptr += scalarLen

	// Get IPP
	err = proof.ipp.UnmarshalBinary(data[ptr:])
	if err != nil {
		return errors.New("rangeProof UnmarshalBinary")
	}

	return nil
}

// checkRange validates whether some scalar v is within the range [0, 2^n - 1]
// It will return an error if v is less than 0 or greater than 2^n - 1
// Otherwise it will return nil.
func checkRange(v curves.Scalar, n int) error {
	bigOne := big.NewInt(1)
	if n < 0 {
		return errors.New("n cannot be less than 0")
	}
	var bigTwoToN big.Int
	bigTwoToN.Lsh(bigOne, uint(n))
	if v.BigInt().Cmp(&bigTwoToN) == 1 {
		return errors.New("v is greater than 2^n")
	}

	return nil
}

// getBlindingVector returns a vector of scalars used as blinding factors for commitments.
func getBlindingVector(length int, curve curves.Curve) []curves.Scalar {
	vec := make([]curves.Scalar, length)
	for i := 0; i < length; i++ {
		vec[i] = curve.Scalar.Random(crand.Reader)
	}
	return vec
}

// getcapV returns a commitment to v using blinding factor gamma.
func getcapV(v, gamma curves.Scalar, g, h curves.Point) curves.Point {
	return h.Mul(gamma).Add(g.Mul(v))
}

// getaL obtains the bit vector representation of v
// See the a_L definition towards the bottom of pg 17 of https://eprint.iacr.org/2017/1066.pdf
func getaL(v curves.Scalar, n int, curve curves.Curve) ([]curves.Scalar, error) {
	var err error

	vBytes := v.Bytes()
	zero := curve.Scalar.Zero()
	one := curve.Scalar.One()
	aL := make([]curves.Scalar, n)
	for j := 0; j < len(aL); j++ {
		aL[j] = zero
	}
	for i := 0; i < n; i++ {
		ithBit := vBytes[i>>3] >> (i & 0x07) & 0x01
		aL[i], err = cmoveScalar(zero, one, int(ithBit), curve)
		if err != nil {
			return nil, errors.Wrap(err, "getaL")
		}
	}

	return aL, nil
}

// cmoveScalar provides a constant time operation that returns x if which is 0 and returns y if which is 1.
func cmoveScalar(x, y curves.Scalar, which int, curve curves.Curve) (curves.Scalar, error) {
	if which != 0 && which != 1 {
		return nil, errors.New("cmoveScalar which must be 0 or 1")
	}
	mask := -byte(which)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	for i, xByte := range xBytes {
		xBytes[i] ^= (xByte ^ yBytes[i]) & mask
	}
	out, err := curve.NewScalar().SetBytes(xBytes)
	if err != nil {
		return nil, errors.Wrap(err, "cmoveScalar SetBytes")
	}

	return out, nil
}

// calcyz uses a merlin transcript for Fiat Shamir
// It takes the current state of the transcript and appends the newly calculated capA and capS values
// Two new scalars are then read from the transcript
// See section 4.4 pg22 of https://eprint.iacr.org/2017/1066.pdf
func calcyz(capV, capA, capS curves.Point, transcript *merlin.Transcript, curve curves.Curve) (curves.Scalar, curves.Scalar, error) {
	// Add the A,S values to transcript
	transcript.AppendMessage([]byte("addV"), capV.ToAffineUncompressed())
	transcript.AppendMessage([]byte("addcapA"), capA.ToAffineUncompressed())
	transcript.AppendMessage([]byte("addcapS"), capS.ToAffineUncompressed())
	// Read 64 bytes twice from, set to scalar for y and z
	yBytes := transcript.ExtractBytes([]byte("gety"), 64)
	y, err := curve.NewScalar().SetBytesWide(yBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "calcyz NewScalar SetBytesWide")
	}
	zBytes := transcript.ExtractBytes([]byte("getz"), 64)
	z, err := curve.NewScalar().SetBytesWide(zBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "calcyz NewScalar SetBytesWide")
	}

	return y, z, nil
}

// calcx uses a merlin transcript for Fiat Shamir
// It takes the current state of the transcript and appends the newly calculated capT1 and capT2 values
// A new scalar is then read from the transcript
// See section 4.4 pg22 of https://eprint.iacr.org/2017/1066.pdf
func calcx(capT1, capT2 curves.Point, transcript *merlin.Transcript, curve curves.Curve) (curves.Scalar, error) {
	// Add the Tau1,2 values to transcript
	transcript.AppendMessage([]byte("addcapT1"), capT1.ToAffineUncompressed())
	transcript.AppendMessage([]byte("addcapT2"), capT2.ToAffineUncompressed())
	// Read 64 bytes from, set to scalar
	outBytes := transcript.ExtractBytes([]byte("getx"), 64)
	x, err := curve.NewScalar().SetBytesWide(outBytes)
	if err != nil {
		return nil, errors.Wrap(err, "calcx NewScalar SetBytesWide")
	}

	return x, nil
}
