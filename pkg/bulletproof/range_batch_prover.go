package bulletproof

import (
	crand "crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// BatchProve proves that a list of scalars v are in the range n.
// It implements the aggregating logarithmic proofs defined on pg21.
// Instead of taking a single value and a single blinding factor, BatchProve takes in a list of values and list of
// blinding factors.
func (prover *RangeProver) BatchProve(v, gamma []curves.Scalar, n int, proofGenerators RangeProofGenerators, transcript *merlin.Transcript) (*RangeProof, error) {
	// Define nm as the total bits required for secrets, calculated as number of secrets * n
	m := len(v)
	nm := n * m
	// nm must be less than or equal to the number of generators generated
	if nm > len(prover.generators.G) {
		return nil, errors.New("ipp vector length must be less than or equal to maxVectorLength")
	}

	// In case where nm is less than number of generators precomputed by prover, trim to length
	proofG := prover.generators.G[0:nm]
	proofH := prover.generators.H[0:nm]

	// Check that each elem in v is in range [0, 2^n]
	for _, vi := range v {
		checkedRange := checkRange(vi, n)
		if checkedRange != nil {
			return nil, checkedRange
		}
	}

	// L40 on pg19
	aL, err := getaLBatched(v, n, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	onenm := get1nVector(nm, prover.curve)
	// L41 on pg19
	aR, err := subtractPairwiseScalarVectors(aL, onenm)
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
	sL := getBlindingVector(nm, prover.curve)
	sR := getBlindingVector(nm, prover.curve)
	rho := prover.curve.Scalar.Random(crand.Reader)

	// Calc S (L47, pg19)
	hrho := proofGenerators.h.Mul(rho)
	gsL := prover.curve.Point.SumOfProducts(proofG, sL)
	hsR := prover.curve.Point.SumOfProducts(proofH, sR)
	capS := hrho.Add(gsL).Add(hsR)

	// Fiat Shamir for y,z (L49, pg19)
	capV := getcapVBatched(v, gamma, proofGenerators.g, proofGenerators.h)
	y, z, err := calcyzBatched(capV, capA, capS, transcript, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc t_1, t_2
	// See the l(X), r(X), equations on pg 21
	// Use l(X)'s and r(X)'s constant and linear terms to derive t_1 and t_2
	// (a_l - z*1^n)
	zonenm := multiplyScalarToScalarVector(z, onenm)
	constantTerml, err := subtractPairwiseScalarVectors(aL, zonenm)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	linearTerml := sL

	// zSum term, see equation 71 on pg21
	zSum := getSumTermrXBatched(z, n, len(v), prover.curve)
	// a_r + z*1^nm
	aRPluszonenm, err := addPairwiseScalarVectors(aR, zonenm)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	ynm := getknVector(y, nm, prover.curve)
	hadamard, err := multiplyPairwiseScalarVectors(ynm, aRPluszonenm)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	constantTermr, err := addPairwiseScalarVectors(hadamard, zSum)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	linearTermr, err := multiplyPairwiseScalarVectors(ynm, sR)
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

	// Calc l
	// Instead of using the expression in the line, evaluate l() at x
	sLx := multiplyScalarToScalarVector(x, linearTerml)
	l, err := addPairwiseScalarVectors(constantTerml, sLx)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc r
	// Instead of using the expression in the line, evaluate r() at x
	ynsRx := multiplyScalarToScalarVector(x, linearTermr)
	r, err := addPairwiseScalarVectors(constantTermr, ynsRx)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// Calc t hat
	// For efficiency, instead of calculating the dot product, evaluate t() at x
	zm := getknVector(z, m, prover.curve)
	zsquarezm := multiplyScalarToScalarVector(z.Square(), zm)
	sumv := prover.curve.Scalar.Zero()
	for i := 0; i < m; i++ {
		elem := zsquarezm[i].Mul(v[i])
		sumv = sumv.Add(elem)
	}

	deltayzBatched, err := deltayzBatched(y, z, n, m, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}
	t0 := sumv.Add(deltayzBatched)
	tLinear := t1.Mul(x)
	tQuadratic := t2.Mul(x.Square())
	tHat := t0.Add(tLinear).Add(tQuadratic)

	// Calc tau_x (L61, pg20)
	tau2xsquare := tau2.Mul(x.Square())
	tau1x := tau1.Mul(x)
	zsum := prover.curve.Scalar.Zero()
	zExp := z.Clone()
	for j := 1; j < m+1; j++ {
		zExp = zExp.Mul(z)
		zsum = zsum.Add(zExp.Mul(gamma[j-1]))
	}
	taux := tau2xsquare.Add(tau1x).Add(zsum)

	// Calc mu (L62, pg20)
	mu := alpha.Add(rho.Mul(x))

	// Calc IPP (See section 4.2)
	hPrime, err := gethPrime(proofH, y, prover.curve)
	if err != nil {
		return nil, errors.Wrap(err, "rangeproof prove")
	}

	// P is redefined in batched case, see bottom equation on pg21.
	capPhmu := getPhmuBatched(proofG, hPrime, proofGenerators.h, capA, capS, x, y, z, mu, n, m, prover.curve)

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

// See final term of L71 on pg 21
// Sigma_{j=1}^{m} z^{1+j} * (0^{(j-1)*n} || 2^{n} || 0^{(m-j)*n}).
func getSumTermrXBatched(z curves.Scalar, n, m int, curve curves.Curve) []curves.Scalar {
	twoN := get2nVector(n, curve)
	var out []curves.Scalar
	// The final power should be one more than m
	zExp := z.Clone()
	for j := 0; j < m; j++ {
		zExp = zExp.Mul(z)
		elem := multiplyScalarToScalarVector(zExp, twoN)
		out = append(out, elem...)
	}

	return out
}

func getcapVBatched(v, gamma []curves.Scalar, g, h curves.Point) []curves.Point {
	out := make([]curves.Point, len(v))
	for i, vi := range v {
		out[i] = getcapV(vi, gamma[i], g, h)
	}
	return out
}

func getaLBatched(v []curves.Scalar, n int, curve curves.Curve) ([]curves.Scalar, error) {
	var aL []curves.Scalar
	for _, vi := range v {
		aLi, err := getaL(vi, n, curve)
		if err != nil {
			return nil, err
		}
		aL = append(aL, aLi...)
	}
	return aL, nil
}

func calcyzBatched(capV []curves.Point, capA, capS curves.Point, transcript *merlin.Transcript, curve curves.Curve) (curves.Scalar, curves.Scalar, error) {
	// Add the A,S values to transcript
	for _, capVi := range capV {
		transcript.AppendMessage([]byte("addV"), capVi.ToAffineUncompressed())
	}
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

func deltayzBatched(y, z curves.Scalar, n, m int, curve curves.Curve) (curves.Scalar, error) {
	// z - z^2
	zMinuszsquare := z.Sub(z.Square())
	// 1^(n*m)
	onenm := get1nVector(n*m, curve)
	// <1^nm, y^nm>
	onenmdotynm, err := innerProduct(onenm, getknVector(y, n*m, curve))
	if err != nil {
		return nil, errors.Wrap(err, "deltayz")
	}
	// (z - z^2)*<1^n, y^n>
	termFirst := zMinuszsquare.Mul(onenmdotynm)

	// <1^n, 2^n>
	onendottwon, err := innerProduct(get1nVector(n, curve), get2nVector(n, curve))
	if err != nil {
		return nil, errors.Wrap(err, "deltayz")
	}

	termSecond := curve.Scalar.Zero()
	zExp := z.Square()
	for j := 1; j < m+1; j++ {
		zExp = zExp.Mul(z)
		elem := zExp.Mul(onendottwon)
		termSecond = termSecond.Add(elem)
	}

	// (z - z^2)*<1^n, y^n> - z^3*<1^n, 2^n>
	out := termFirst.Sub(termSecond)

	return out, nil
}

// Bottom equation on pg21.
func getPhmuBatched(proofG, proofHPrime []curves.Point, h, capA, capS curves.Point, x, y, z, mu curves.Scalar, n, m int, curve curves.Curve) curves.Point {
	twoN := get2nVector(n, curve)
	// h'^(z*y^n + z^2*2^n)
	lastElem := curve.NewIdentityPoint()
	zExp := z.Clone()
	for j := 1; j < m+1; j++ {
		// Get subvector of h
		hSubvector := proofHPrime[(j-1)*n : j*n]
		// z^(j+1)
		zExp = zExp.Mul(z)
		exp := multiplyScalarToScalarVector(zExp, twoN)
		// Final elem
		elem := curve.Point.SumOfProducts(hSubvector, exp)
		lastElem = lastElem.Add(elem)
	}

	zynm := multiplyScalarToScalarVector(z, getknVector(y, n*m, curve))
	hPrimezynm := curve.Point.SumOfProducts(proofHPrime, zynm)
	lastElem = lastElem.Add(hPrimezynm)

	// S^x
	capSx := capS.Mul(x)

	// g^-z --> -z*<1,g>
	onenm := get1nVector(n*m, curve)
	zNeg := z.Neg()
	zinvonen := multiplyScalarToScalarVector(zNeg, onenm)
	zgdotonen := curve.Point.SumOfProducts(proofG, zinvonen)

	// L66 on pg20
	P := capA.Add(capSx).Add(zgdotonen).Add(lastElem)
	hmu := h.Mul(mu)
	Phmu := P.Sub(hmu)

	return Phmu
}
