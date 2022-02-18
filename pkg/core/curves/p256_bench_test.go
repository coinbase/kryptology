//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core"
	"io"
	"math/big"
	"testing"
)

func BenchmarkP256(b *testing.B) {
	// 1000 points

	b.Run("1000 point hash - p256", func(b *testing.B) {
		b.StopTimer()
		points := make([][]byte, 1000)
		for i := range points {
			t := make([]byte, 32)
			_, _ = crand.Read(t)
			points[i] = t
		}
		acc := new(BenchPointP256).Identity()
		b.StartTimer()
		for _, pt := range points {
			acc = acc.Hash(pt)
		}
	})

	b.Run("1000 point hash - ct p256", func(b *testing.B) {
		b.StopTimer()
		points := make([][]byte, 1000)
		for i := range points {
			t := make([]byte, 32)
			_, _ = crand.Read(t)
			points[i] = t
		}
		acc := new(PointP256).Identity()
		b.StartTimer()
		for _, pt := range points {
			acc = acc.Hash(pt)
		}
	})

	b.Run("1000 point add - p256", func(b *testing.B) {
		b.StopTimer()
		points := make([]*BenchPointP256, 1000)
		for i := range points {
			points[i] = points[i].Random(crand.Reader).(*BenchPointP256)
		}
		acc := new(BenchPointP256).Identity()
		b.StartTimer()
		for _, pt := range points {
			acc = acc.Add(pt)
		}
	})
	b.Run("1000 point add - ct p256", func(b *testing.B) {
		b.StopTimer()
		curve := P256()
		points := make([]*PointP256, 1000)
		for i := range points {
			points[i] = curve.NewIdentityPoint().Random(crand.Reader).(*PointP256)
		}
		acc := curve.NewIdentityPoint()
		b.StartTimer()
		for _, pt := range points {
			acc = acc.Add(pt)
		}
	})
	b.Run("1000 point double - p256", func(b *testing.B) {
		b.StopTimer()
		acc := new(BenchPointP256).Generator()
		b.StartTimer()
		for i := 0; i < 1000; i++ {
			acc = acc.Double()
		}
	})
	b.Run("1000 point double - ct p256", func(b *testing.B) {
		b.StopTimer()
		acc := new(PointP256).Generator()
		b.StartTimer()
		for i := 0; i < 1000; i++ {
			acc = acc.Double()
		}
	})
	b.Run("1000 point multiply - p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*BenchScalarP256, 1000)
		for i := range scalars {
			s := new(BenchScalarP256).Random(crand.Reader)
			scalars[i] = s.(*BenchScalarP256)
		}
		acc := new(BenchPointP256).Generator().Mul(new(BenchScalarP256).New(2))
		b.StartTimer()
		for _, sc := range scalars {
			acc = acc.Mul(sc)
		}
	})
	b.Run("1000 point multiply - ct p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*ScalarP256, 1000)
		for i := range scalars {
			s := new(ScalarP256).Random(crand.Reader)
			scalars[i] = s.(*ScalarP256)
		}
		acc := new(PointP256).Generator()
		b.StartTimer()
		for _, sc := range scalars {
			acc = acc.Mul(sc)
		}
	})
	b.Run("1000 scalar invert - p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*BenchScalarP256, 1000)
		for i := range scalars {
			s := new(BenchScalarP256).Random(crand.Reader)
			scalars[i] = s.(*BenchScalarP256)
		}
		b.StartTimer()
		for _, sc := range scalars {
			_, _ = sc.Invert()
		}
	})
	b.Run("1000 scalar invert - ct p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*ScalarP256, 1000)
		for i := range scalars {
			s := new(ScalarP256).Random(crand.Reader)
			scalars[i] = s.(*ScalarP256)
		}
		b.StartTimer()
		for _, sc := range scalars {
			_, _ = sc.Invert()
		}
	})
	b.Run("1000 scalar sqrt - p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*BenchScalarP256, 1000)
		for i := range scalars {
			s := new(BenchScalarP256).Random(crand.Reader)
			scalars[i] = s.(*BenchScalarP256)
		}
		b.StartTimer()
		for _, sc := range scalars {
			_, _ = sc.Sqrt()
		}
	})
	b.Run("1000 scalar sqrt - ct p256", func(b *testing.B) {
		b.StopTimer()
		scalars := make([]*ScalarP256, 1000)
		for i := range scalars {
			s := new(ScalarP256).Random(crand.Reader)
			scalars[i] = s.(*ScalarP256)
		}
		b.StartTimer()
		for _, sc := range scalars {
			_, _ = sc.Sqrt()
		}
	})
}

type BenchScalarP256 struct {
	value *big.Int
}

type BenchPointP256 struct {
	x, y *big.Int
}

func (s *BenchScalarP256) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *BenchScalarP256) Hash(bytes []byte) Scalar {
	xmd, err := expandMsgXmd(sha256.New(), bytes, []byte("P256_XMD:SHA-256_SSWU_RO_"), 48)
	if err != nil {
		return nil
	}
	v := new(big.Int).SetBytes(xmd)
	return &BenchScalarP256{
		value: v.Mod(v, elliptic.P256().Params().N),
	}
}

func (s *BenchScalarP256) Zero() Scalar {
	return &BenchScalarP256{
		value: big.NewInt(0),
	}
}

func (s *BenchScalarP256) One() Scalar {
	return &BenchScalarP256{
		value: big.NewInt(1),
	}
}

func (s *BenchScalarP256) IsZero() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{}) == 1
}

func (s *BenchScalarP256) IsOne() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{1}) == 1
}

func (s *BenchScalarP256) IsOdd() bool {
	return s.value.Bit(0) == 1
}

func (s *BenchScalarP256) IsEven() bool {
	return s.value.Bit(0) == 0
}

func (s *BenchScalarP256) New(value int) Scalar {
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, elliptic.P256().Params().N)
	}
	return &BenchScalarP256{
		value: v,
	}
}

func (s *BenchScalarP256) Cmp(rhs Scalar) int {
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *BenchScalarP256) Square() Scalar {
	return &BenchScalarP256{
		value: new(big.Int).Exp(s.value, big.NewInt(2), elliptic.P256().Params().N),
	}
}

func (s *BenchScalarP256) Double() Scalar {
	v := new(big.Int).Add(s.value, s.value)
	return &BenchScalarP256{
		value: v.Mod(v, elliptic.P256().Params().N),
	}
}

func (s *BenchScalarP256) Invert() (Scalar, error) {
	return &BenchScalarP256{
		value: new(big.Int).ModInverse(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *BenchScalarP256) Sqrt() (Scalar, error) {
	return &BenchScalarP256{
		value: new(big.Int).ModSqrt(s.value, elliptic.P256().Params().N),
	}, nil
}

func (s *BenchScalarP256) Cube() Scalar {
	return &BenchScalarP256{
		value: new(big.Int).Exp(s.value, big.NewInt(3), elliptic.P256().Params().N),
	}
}

func (s *BenchScalarP256) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		v := new(big.Int).Add(s.value, r.value)
		return &BenchScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalarP256) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		v := new(big.Int).Sub(s.value, r.value)
		return &BenchScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalarP256) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		v := new(big.Int).Mul(s.value, r.value)
		return &BenchScalarP256{
			value: v.Mod(v, elliptic.P256().Params().N),
		}
	} else {
		return nil
	}
}

func (s *BenchScalarP256) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *BenchScalarP256) Div(rhs Scalar) Scalar {
	n := elliptic.P256().Params().N
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		v := new(big.Int).ModInverse(r.value, n)
		v.Mul(v, s.value)
		return &BenchScalarP256{
			value: v.Mod(v, n),
		}
	} else {
		return nil
	}
}

func (s *BenchScalarP256) Neg() Scalar {
	z := new(big.Int).Neg(s.value)
	return &BenchScalarP256{
		value: z.Mod(z, elliptic.P256().Params().N),
	}
}

func (s *BenchScalarP256) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := new(big.Int).Mod(v, elliptic.P256().Params().N)
	if t.Cmp(v) != 0 {
		return nil, fmt.Errorf("invalid value")
	}
	return &BenchScalarP256{
		value: t,
	}, nil
}

func (s *BenchScalarP256) BigInt() *big.Int {
	return new(big.Int).Set(s.value)
}

func (s *BenchScalarP256) Bytes() []byte {
	var out [32]byte
	return s.value.FillBytes(out[:])
}

func (s *BenchScalarP256) SetBytes(bytes []byte) (Scalar, error) {
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, elliptic.P256().Params().N)
	if t.Cmp(value) != 0 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	return &BenchScalarP256{
		value: t,
	}, nil
}

func (s *BenchScalarP256) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) < 32 || len(bytes) > 128 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := new(big.Int).SetBytes(bytes)
	value.Mod(value, elliptic.P256().Params().N)
	return &BenchScalarP256{
		value,
	}, nil
}

func (s *BenchScalarP256) Point() Point {
	return new(BenchPointP256).Identity()
}

func (s *BenchScalarP256) Clone() Scalar {
	return &BenchScalarP256{
		value: new(big.Int).Set(s.value),
	}
}

func (s *BenchScalarP256) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *BenchScalarP256) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*BenchScalarP256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalarP256) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *BenchScalarP256) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*BenchScalarP256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *BenchScalarP256) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *BenchScalarP256) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*BenchScalarP256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *BenchPointP256) Random(reader io.Reader) Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *BenchPointP256) Hash(bytes []byte) Point {
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

	return &BenchPointP256{
		x, y,
	}
}

func (p *BenchPointP256) Identity() Point {
	return &BenchPointP256{
		x: big.NewInt(0), y: big.NewInt(0),
	}
}

func (p *BenchPointP256) Generator() Point {
	curve := elliptic.P256().Params()
	return &BenchPointP256{
		x: new(big.Int).Set(curve.Gx),
		y: new(big.Int).Set(curve.Gy),
	}
}

func (p *BenchPointP256) IsIdentity() bool {
	x := core.ConstantTimeEqByte(p.x, core.Zero)
	y := core.ConstantTimeEqByte(p.y, core.Zero)
	return (x & y) == 1
}

func (p *BenchPointP256) IsNegative() bool {
	return p.y.Bit(0) == 1
}

func (p *BenchPointP256) IsOnCurve() bool {
	return elliptic.P256().IsOnCurve(p.x, p.y)
}

func (p *BenchPointP256) Double() Point {
	curve := elliptic.P256()
	x, y := curve.Double(p.x, p.y)
	return &BenchPointP256{x, y}
}

func (p *BenchPointP256) Scalar() Scalar {
	return new(BenchScalarP256).Zero()
}

func (p *BenchPointP256) Neg() Point {
	y := new(big.Int).Sub(elliptic.P256().Params().P, p.y)
	y.Mod(y, elliptic.P256().Params().P)
	return &BenchPointP256{x: p.x, y: y}
}

func (p *BenchPointP256) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*BenchPointP256)
	if ok {
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &BenchPointP256{x, y}
	} else {
		return nil
	}
}

func (p *BenchPointP256) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.Neg().(*BenchPointP256)
	if ok {
		x, y := elliptic.P256().Add(p.x, p.y, r.x, r.y)
		return &BenchPointP256{x, y}
	} else {
		return nil
	}
}

func (p *BenchPointP256) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*BenchScalarP256)
	if ok {
		x, y := elliptic.P256().ScalarMult(p.x, p.y, r.value.Bytes())
		return &BenchPointP256{x, y}
	} else {
		return nil
	}
}

func (p *BenchPointP256) Equal(rhs Point) bool {
	r, ok := rhs.(*BenchPointP256)
	if ok {
		x := core.ConstantTimeEqByte(p.x, r.x)
		y := core.ConstantTimeEqByte(p.y, r.y)
		return (x & y) == 1
	} else {
		return false
	}
}

func (p *BenchPointP256) Set(x, y *big.Int) (Point, error) {
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
	return &BenchPointP256{x, y}, nil
}

func (p *BenchPointP256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)
	x[0] |= byte(p.y.Bit(0))
	p.x.FillBytes(x[1:])
	return x[:]
}

func (p *BenchPointP256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out[:]
}

func (p *BenchPointP256) FromAffineCompressed(bytes []byte) (Point, error) {
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
	return &BenchPointP256{
		x, y,
	}, nil
}

func (p *BenchPointP256) FromAffineUncompressed(bytes []byte) (Point, error) {
	if len(bytes) != 65 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	if bytes[0] != 4 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:])
	return &BenchPointP256{x, y}, nil
}

func (p *BenchPointP256) CurveName() string {
	return elliptic.P256().Params().Name
}

func (p *BenchPointP256) SumOfProducts(points []Point, scalars []Scalar) Point {
	nScalars := make([]*big.Int, len(scalars))
	for i, sc := range scalars {
		s, ok := sc.(*BenchScalarP256)
		if !ok {
			return nil
		}
		nScalars[i] = s.value
	}
	return sumOfProductsPippenger(points, nScalars)
}

func (p *BenchPointP256) X() *big.Int {
	return new(big.Int).Set(p.x)
}

func (p *BenchPointP256) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func (p *BenchPointP256) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *BenchPointP256) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *BenchPointP256) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*BenchPointP256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *BenchPointP256) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *BenchPointP256) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*BenchPointP256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *BenchPointP256) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *BenchPointP256) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*BenchPointP256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.x = P.x
	p.y = P.y
	return nil
}

// From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.2
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

//rhs of the curve equation
func rhsP256(x *big.Int, params *elliptic.CurveParams) *big.Int {
	f := NewField(params.P)
	r := f.NewElement(x)
	r2 := r.Mul(r)

	// x^3-3x+B
	a := r.Mul(f.NewElement(big.NewInt(3)))
	r = r2.Mul(r)
	return r.Add(a.Neg()).Add(f.NewElement(params.B)).Value
}
