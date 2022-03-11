//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"errors"
	"fmt"

	"git.sr.ht/~sircmpwn/go-bare"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// MembershipWitness contains the witness c and the value y respect to the accumulator state.
type MembershipWitness struct {
	c curves.Point
	y curves.Scalar
}

// New creates a new membership witness
func (mw *MembershipWitness) New(y Element, acc *Accumulator, sk *SecretKey) (*MembershipWitness, error) {
	if acc.value == nil || acc.value.IsIdentity() {
		return nil, fmt.Errorf("value of accumulator should not be nil")
	}
	if sk.value == nil || sk.value.IsZero() {
		return nil, fmt.Errorf("secret key should not be nil")
	}
	if y == nil || y.IsZero() {
		return nil, fmt.Errorf("y should not be nil")
	}
	newAcc := &Accumulator{acc.value}
	_, err := newAcc.Remove(sk, y)
	if err != nil {
		return nil, err
	}
	mw.c = newAcc.value
	mw.y = y.Add(y.Zero())
	return mw, nil
}

// Verify the MembershipWitness mw is a valid witness as per section 4 in
// <https://eprint.iacr.org/2020/777>
func (mw MembershipWitness) Verify(pk *PublicKey, acc *Accumulator) error {
	if mw.c == nil || mw.y == nil || mw.c.IsIdentity() || mw.y.IsZero() {
		return fmt.Errorf("c and y should not be nil")
	}

	if pk.value == nil || pk.value.IsIdentity() {
		return fmt.Errorf("invalid public key")
	}
	if acc.value == nil || acc.value.IsIdentity() {
		return fmt.Errorf("accumulator value should not be nil")
	}

	// Set -tildeP
	g2, ok := pk.value.Generator().(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	// y*tildeP + tildeQ, tildeP is a G2 generator.
	p, ok := g2.Mul(mw.y).Add(pk.value).(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	// Prepare
	witness, ok := mw.c.(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}
	v, ok := acc.value.Neg().(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	// Check e(witness, y*tildeP + tildeQ) * e(-acc, tildeP) == Identity
	result := p.MultiPairing(witness, p, v, g2)
	if !result.IsOne() {
		return fmt.Errorf("invalid result")
	}

	return nil
}

// ApplyDelta returns C' = dA(y)/dD(y)*C + 1/dD(y) * <Gamma_y, Omega>
// according to the witness update protocol described in section 4 of
// https://eprint.iacr.org/2020/777.pdf
func (mw *MembershipWitness) ApplyDelta(delta *Delta) (*MembershipWitness, error) {
	if mw.c == nil || mw.y == nil || delta == nil {
		return nil, fmt.Errorf("y, c or delta should not be nil")
	}

	// C' = dA(y)/dD(y)*C + 1/dD(y) * <Gamma_y, Omega>
	mw.c = mw.c.Mul(delta.d).Add(delta.p)
	return mw, nil
}

// BatchUpdate performs batch update as described in section 4
func (mw *MembershipWitness) BatchUpdate(additions []Element, deletions []Element, coefficients []Coefficient) (*MembershipWitness, error) {
	delta, err := evaluateDelta(mw.y, additions, deletions, coefficients)
	if err != nil {
		return nil, err
	}
	mw, err = mw.ApplyDelta(delta)
	if err != nil {
		return nil, fmt.Errorf("applyDelta fails")
	}
	return mw, nil
}

// MultiBatchUpdate performs multi-batch update using epoch as described in section 4.2
func (mw *MembershipWitness) MultiBatchUpdate(A [][]Element, D [][]Element, C [][]Coefficient) (*MembershipWitness, error) {
	delta, err := evaluateDeltas(mw.y, A, D, C)
	if err != nil {
		return nil, fmt.Errorf("evaluateDeltas fails")
	}
	mw, err = mw.ApplyDelta(delta)
	if err != nil {
		return nil, err
	}
	return mw, nil
}

// MarshalBinary converts a membership witness to bytes
func (mw MembershipWitness) MarshalBinary() ([]byte, error) {
	if mw.c == nil || mw.y == nil {
		return nil, fmt.Errorf("c and y value should not be nil")
	}

	result := append(mw.c.ToAffineCompressed(), mw.y.Bytes()...)
	tv := &structMarshal{
		Value: result,
		Curve: mw.c.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary converts bytes into MembershipWitness
func (mw *MembershipWitness) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("input data should not be nil")
	}
	tv := new(structMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}

	ptLength := len(curve.Point.ToAffineCompressed())
	scLength := len(curve.Scalar.Bytes())
	expectedLength := ptLength + scLength
	if len(tv.Value) != expectedLength {
		return fmt.Errorf("invalid byte sequence")
	}
	cValue, err := curve.Point.FromAffineCompressed(tv.Value[:ptLength])
	if err != nil {
		return err
	}
	yValue, err := curve.Scalar.SetBytes(tv.Value[ptLength:])
	if err != nil {
		return err
	}
	mw.c = cValue
	mw.y = yValue
	return nil
}

// Delta contains values d and p, where d should be the division dA(y)/dD(y) on some value y
// p should be equal to 1/dD * <Gamma_y, Omega>
type Delta struct {
	d curves.Scalar
	p curves.Point
}

// MarshalBinary converts Delta into bytes
func (d *Delta) MarshalBinary() ([]byte, error) {
	if d.d == nil || d.p == nil {
		return nil, fmt.Errorf("d and p should not be nil")
	}
	var result []byte
	result = append(result, d.p.ToAffineCompressed()...)
	result = append(result, d.d.Bytes()...)
	tv := &structMarshal{
		Value: result,
		Curve: d.p.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary converts data into Delta
func (d *Delta) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("expected non-zero byte sequence")
	}

	tv := new(structMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}

	ptLength := len(curve.Point.ToAffineCompressed())
	scLength := len(curve.Scalar.Bytes())
	expectedLength := ptLength + scLength
	if len(tv.Value) != expectedLength {
		return fmt.Errorf("invalid byte sequence")
	}
	pValue, err := curve.NewIdentityPoint().FromAffineCompressed(tv.Value[:ptLength])
	if err != nil {
		return err
	}
	dValue, err := curve.NewScalar().SetBytes(tv.Value[ptLength:])
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	d.d = dValue
	d.p = pValue
	return nil
}

// evaluateDeltas compute values used for membership witness batch update with epoch
// as described in section 4.2, page 11 of https://eprint.iacr.org/2020/777.pdf
func evaluateDeltas(y Element, A [][]Element, D [][]Element, C [][]Coefficient) (*Delta, error) {
	if len(A) != len(D) || len(A) != len(C) {
		return nil, fmt.Errorf("a, d, c should have same length")
	}

	one := y.One()
	size := len(A)

	// dA(x) =  ∏ 1..n (yA_i - x)
	aa := make([]curves.Scalar, 0)
	// dD(x) = ∏ 1..m (yD_i - x)
	dd := make([]curves.Scalar, 0)

	a := one
	d := one

	// dA_{a->b}(y) = ∏ a..b dAs(y)
	// dD_{a->b}(y) = ∏ a..b dDs(y)
	for i := 0; i < size; i++ {
		adds := A[i]
		dels := D[i]

		// ta = dAs(y)
		ta, err := dad(adds, y)
		if err != nil {
			return nil, fmt.Errorf("dad on additions fails")
		}
		// td = dDs(y)
		td, err := dad(dels, y)
		if err != nil {
			return nil, fmt.Errorf("dad on deletions fails")
		}
		// ∏ a..b dAs(y)
		a = a.Mul(ta)
		// ∏ a..b dDs(y)
		d = d.Mul(td)

		aa = append(aa, ta)
		dd = append(dd, td)
	}

	// If this fails, then this value was removed.
	d, err := d.Invert()
	if err != nil {
		return nil, fmt.Errorf("no inverse exists")
	}

	// <Gamma_y, Omega>
	p := make(polynomialPoint, 0, size)

	// Ωi->j+1 = ∑ 1..t (dAt * dDt-1) · Ω
	for i := 0; i < size; i++ {
		// t = i+1
		// ∏^(t-1)_(h=i+1)
		ddh := one

		// dDi→t−1 (y)
		for h := 0; h < i; h++ {
			ddh = ddh.Mul(dd[h])
		}

		// ∏^(j+1)_(k=t+1)
		dak := one
		// dAt->j(y)
		for k := i + 1; k < size; k++ {
			dak = dak.Mul(aa[k])
		}

		// dDi->t-1(y) * dAt->j(y)
		dak = dak.Mul(ddh)
		pp := make(polynomialPoint, len(C[i]))
		for j := 0; j < len(pp); j++ {
			pp[j] = C[i][j]
		}

		// dDi->t-1(y) * dAt->j(y) · Ω
		pp, err := pp.Mul(dak)
		if err != nil {
			return nil, fmt.Errorf("pp.Mul fails")
		}

		p, err = p.Add(pp)
		if err != nil {
			return nil, fmt.Errorf("pp.Add fails")
		}
	}
	// dAi->j(y)/dDi->j(y)
	a = a.Mul(d)

	// Ωi->j(y)
	v, err := p.evaluate(y)
	if err != nil {
		return nil, fmt.Errorf("p.evaluate fails")
	}

	// (1/dDi->j(y)) * Ωi->j(y)
	v = v.Mul(d)

	// return
	return &Delta{d: a, p: v}, nil
}

// evaluateDelta computes values used for membership witness batch update
// as described in section 4.1 of https://eprint.iacr.org/2020/777.pdf
func evaluateDelta(y Element, additions []Element, deletions []Element, coefficients []Coefficient) (*Delta, error) {
	// dD(y) = ∏ 1..m (yD_i - y), d = 1/dD(y)
	var err error
	d, err := dad(deletions, y)
	if err != nil {
		return nil, fmt.Errorf("dad fails on deletions")
	}
	d, err = d.Invert()
	if err != nil {
		return nil, fmt.Errorf("no inverse exists")
	}

	//dA(y) =  ∏ 1..n (yA_i - y)
	a, err := dad(additions, y)
	if err != nil {
		return nil, fmt.Errorf("dad fails on additions")
	}
	// dA(y)/dD(y)
	a = a.Mul(d)

	// Create a PolynomialG1 from coefficients
	p := make(polynomialPoint, len(coefficients))
	for i := 0; i < len(coefficients); i++ {
		p[i] = coefficients[i]
	}

	// <Gamma_y, Omega>
	v, err := p.evaluate(y)
	if err != nil {
		return nil, fmt.Errorf("p.evaluate fails")
	}
	// 1/dD * <Gamma_y, Omega>
	v = v.Mul(d)

	return &Delta{d: a, p: v}, nil
}
