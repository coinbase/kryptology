//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core"
	"io"
	"math/big"
)

type ScalarP256 struct {
	value *big.Int
}

type PointP256 struct {
	x, y *big.Int
}

func (s *ScalarP256) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarP256) Hash(bytes []byte) Scalar {
	xmd, err := expandMsgXmd(sha256.New(), bytes, []byte("P256_XMD:SHA-256_SSWU_RO_"), 48)
	if err != nil {
		return nil
	}
	v := new(big.Int).SetBytes(xmd)
	return &ScalarP256{
		value: v.Mod(v, elliptic.P256().Params().N),
	}
}

func (s *ScalarP256) Zero() Scalar {
	return &ScalarP256{
		value: big.NewInt(0),
	}
}

func (s *ScalarP256) One() Scalar {
	return &ScalarP256{
		value: big.NewInt(1),
	}
}

func (s *ScalarP256) IsZero() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{}) == 1
}

func (s *ScalarP256) IsOne() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{1}) == 1
}

func (s *ScalarP256) IsOdd() bool {
	return s.value.Bit(0) == 1
}

func (s *ScalarP256) IsEven() bool {
	return s.value.Bit(0) == 0
}

func (s *ScalarP256) New(value int) Scalar {
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, elliptic.P256().Params().N)
	}
	return &ScalarP256{
		value: v,
	}
}

func (s *ScalarP256) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *ScalarP256) Square() Scalar {
	return &ScalarP256{
		value: new(big.Int).Exp(s.value, big.NewInt(2), elliptic.P256().Params().N),
	}
}

func (s *ScalarP256) Double() Scalar {
	v := new(big.Int).Add(s.value, s.value)
	return &ScalarP256{
		value: v.Mod(v, elliptic.P256().Params().N),
	}
}

func (s *ScalarP256) Invert() (Scalar, error) {
	return &ScalarP256{
		value: new(big.Int).ModInverse(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *ScalarP256) Sqrt() (Scalar, error) {
	return &ScalarP256{
		value: new(big.Int).ModSqrt(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *ScalarP256) Cube() Scalar {
	return &ScalarP256{
		value: new(big.Int).Exp(s.value, big.NewInt(3), elliptic.P256().Params().N),
	}
}

func (s *ScalarP256) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		v := new(big.Int).Add(s.value, r.value)
		return &ScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarP256) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		v := new(big.Int).Sub(s.value, r.value)
		return &ScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarP256) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		v := new(big.Int).Mul(s.value, r.value)
		return &ScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarP256) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarP256) Div(rhs Scalar) Scalar {
	n := elliptic.P256().Params().N
	r, ok := rhs.(*ScalarP256)
	if ok {
		v := new(big.Int).ModInverse(r.value, n)
		v.Mul(v, s.value)
		return &ScalarP256{
			value: v.Mod(v, n),
		}
	} else {
		return nil
	}
}

func (s *ScalarP256) Neg() Scalar {
	z := new(big.Int).Neg(s.value)
	return &ScalarP256{
		value: z.Mod(z, elliptic.P256().Params().N),
	}
}

func (s *ScalarP256) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := new(big.Int).Mod(v, elliptic.P256().Params().N)
	if t.Cmp(v) != 0 {
		return nil, fmt.Errorf("invalid value")
	}
	return &ScalarP256{
		value: t,
	}, nil
}

func (s *ScalarP256) BigInt() *big.Int {
	return new(big.Int).Set(s.value)
}

func (s *ScalarP256) Bytes() []byte {
	var out [32]byte
	return s.value.FillBytes(out[:])
}

func (s *ScalarP256) SetBytes(bytes []byte) (Scalar, error) {
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, elliptic.P256().Params().N)
	if t.Cmp(value) != 0 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	return &ScalarP256{
		value: t,
	}, nil
}

func (s *ScalarP256) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) < 32 || len(bytes) > 128 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := new(big.Int).SetBytes(bytes)
	value.Mod(value, elliptic.P256().Params().N)
	return &ScalarP256{
		value,
	}, nil
}

func (s *ScalarP256) Point() Point {
	return new(PointP256).Identity()
}

func (s *ScalarP256) Clone() Scalar {
	return &ScalarP256{
		value: new(big.Int).Set(s.value),
	}
}

func (s *ScalarP256) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarP256) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarP256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarP256) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarP256) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarP256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarP256) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarP256) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*ScalarP256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *PointP256) Random(reader io.Reader) Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointP256) Hash(bytes []byte) Point {
	curve := elliptic.P256().Params()

	var domain = []byte("P256_XMD:SHA-256_SSWU_RO_")
	uniformBytes, _ := expandMsgXmd(sha256.New(), bytes, domain, 96)

	u0 := new(big.Int).SetBytes(uniformBytes[:48])
	u1 := new(big.Int).SetBytes(uniformBytes[48:])

	u0.Mod(u0, curve.P)
	u1.Mod(u1, curve.P)

	ssParams := p256SswuParams()
	q0x, q0y := osswu3mod4(u0, ssParams)
	q1x, q1y := osswu3mod4(u1, ssParams)

	// Since P-256 does not require the isogeny map just add the points
	x, y := curve.Add(q0x, q0y, q1x, q1y)

	return &PointP256{
		x, y,
	}
}

func (p *PointP256) Identity() Point {
	return &PointP256{
		x: big.NewInt(0), y: big.NewInt(0),
	}
}

func (p *PointP256) Generator() Point {
	curve := elliptic.P256().Params()
	return &PointP256{
		x: new(big.Int).Set(curve.Gx),
		y: new(big.Int).Set(curve.Gy),
	}
}

func (p *PointP256) IsIdentity() bool {
	x := core.ConstantTimeEqByte(p.x, core.Zero)
	y := core.ConstantTimeEqByte(p.y, core.Zero)
	return (x & y) == 1
}

func (p *PointP256) IsNegative() bool {
	return p.y.Bit(0) == 1
}

func (p *PointP256) IsOnCurve() bool {
	return elliptic.P256().IsOnCurve(p.x, p.y)
}

func (p *PointP256) Double() Point {
	curve := elliptic.P256()
	x, y := curve.Double(p.x, p.y)
	return &PointP256{x, y}
}

func (p *PointP256) Scalar() Scalar {
	return new(ScalarP256).Zero()
}

func (p *PointP256) Neg() Point {
	y := new(big.Int).Sub(elliptic.P256().Params().P, p.y)
	y.Mod(y, elliptic.P256().Params().P)
	return &PointP256{x: p.x, y: y}
}

func (p *PointP256) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointP256)
	if ok {
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &PointP256{x, y}
	} else {
		return nil
	}
}

func (p *PointP256) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.Neg().(*PointP256)
	if ok {
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &PointP256{x, y}
	} else {
		return nil
	}
}

func (p *PointP256) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarP256)
	if ok {
		x, y := elliptic.P256().ScalarMult(p.x, p.y, r.value.Bytes())
		return &PointP256{x, y}
	} else {
		return nil
	}
}

func (p *PointP256) Equal(rhs Point) bool {
	r, ok := rhs.(*PointP256)
	if ok {
		x := core.ConstantTimeEqByte(p.x, r.x)
		y := core.ConstantTimeEqByte(p.y, r.y)
		return (x & y) == 1
	} else {
		return false
	}
}

func (p *PointP256) Set(x, y *big.Int) (Point, error) {
	// check is identity or on curve
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	// Checks are constant time
	onCurve := elliptic.P256().IsOnCurve(x, y)
	if !onCurve && (xx&yy) != 1 {
		return nil, fmt.Errorf("invalid coordinates")
	}
	x = new(big.Int).Set(x)
	y = new(big.Int).Set(y)
	return &PointP256{x, y}, nil
}

func (p *PointP256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)
	x[0] |= byte(p.y.Bit(0))
	p.x.FillBytes(x[1:])
	return x[:]
}

func (p *PointP256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out[:]
}

func (p *PointP256) FromAffineCompressed(bytes []byte) (Point, error) {
	if len(bytes) != 33 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sign := int(bytes[0])
	if sign != 2 && sign != 3 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	sign &= 0x1

	x := new(big.Int).SetBytes(bytes[1:])
	rhs := rhsP256(x, elliptic.P256().Params())
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y := new(big.Int).ModSqrt(rhs, elliptic.P256().Params().P)
	if y != nil {
		// fix the sign
		if int(y.Bit(0)) != sign {
			y.Neg(y)
			y.Mod(y, elliptic.P256().Params().P)
		}
	} else {
		x = new(big.Int)
		y = new(big.Int)
	}
	return &PointP256{
		x, y,
	}, nil
}

func (p *PointP256) FromAffineUncompressed(bytes []byte) (Point, error) {
	if len(bytes) != 65 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	if bytes[0] != 4 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:])
	return &PointP256{x, y}, nil
}

func (p *PointP256) CurveName() string {
	return elliptic.P256().Params().Name
}

func (p *PointP256) SumOfProducts(points []Point, scalars []Scalar) Point {
	nScalars := make([]*big.Int, len(scalars))
	for i, sc := range scalars {
		s, ok := sc.(*ScalarP256)
		if !ok {
			return nil
		}
		nScalars[i] = s.value
	}
	return sumOfProductsPippenger(points, nScalars)
}

func (p *PointP256) X() *big.Int {
	return new(big.Int).Set(p.x)
}

func (p *PointP256) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func (p *PointP256) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *PointP256) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointP256) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointP256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *PointP256) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointP256) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointP256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *PointP256) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointP256) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointP256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.x = P.x
	p.y = P.y
	return nil
}

// Take from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.2
func p256SswuParams() *sswuParams {
	params := elliptic.P256().Params()

	// c1 = (q - 3) / 4
	c1 := new(big.Int).Set(params.P)
	c1.Sub(c1, big.NewInt(3))
	c1.Rsh(c1, 2)

	a := big.NewInt(-3)
	a.Mod(a, params.P)
	b := new(big.Int).Set(params.B)
	z := big.NewInt(-10)
	z.Mod(z, params.P)
	// sqrt(-Z^3)
	zTmp := new(big.Int).Exp(z, big.NewInt(3), nil)
	zTmp = zTmp.Neg(zTmp)
	zTmp.Mod(zTmp, params.P)
	c2 := new(big.Int).ModSqrt(zTmp, params.P)

	return &sswuParams{
		params, c1, c2, a, b, z,
	}
}

// rhs of the curve equation
func rhsP256(x *big.Int, params *elliptic.CurveParams) *big.Int {
	f := NewField(params.P)
	r := f.NewElement(x)
	r2 := r.Mul(r)

	// x^3-3x+B
	a := r.Mul(f.NewElement(big.NewInt(3)))
	r = r2.Mul(r)
	return r.Add(a.Neg()).Add(f.NewElement(params.B)).Value
}
