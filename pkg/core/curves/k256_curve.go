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
	"github.com/btcsuite/btcd/btcec"
	"io"
	"math/big"
)

type ScalarK256 struct {
	value *big.Int
}

type PointK256 struct {
	x, y *big.Int
}

func (s *ScalarK256) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarK256) Hash(bytes []byte) Scalar {
	xmd, err := expandMsgXmd(sha256.New(), bytes, []byte("secp256k1_XMD:SHA-256_SSWU_RO_"), 48)
	if err != nil {
		return nil
	}
	v := new(big.Int).SetBytes(xmd)
	return &ScalarK256{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *ScalarK256) Zero() Scalar {
	return &ScalarK256{
		value: big.NewInt(0),
	}
}

func (s *ScalarK256) One() Scalar {
	return &ScalarK256{
		value: big.NewInt(1),
	}
}

func (s *ScalarK256) IsZero() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{}) == 1
}

func (s *ScalarK256) IsOne() bool {
	return subtle.ConstantTimeCompare(s.value.Bytes(), []byte{1}) == 1
}

func (s *ScalarK256) IsOdd() bool {
	return s.value.Bit(0) == 1
}

func (s *ScalarK256) IsEven() bool {
	return s.value.Bit(0) == 0
}

func (s *ScalarK256) New(value int) Scalar {
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, btcec.S256().N)
	}
	return &ScalarK256{
		value: v,
	}
}

func (s *ScalarK256) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *ScalarK256) Square() Scalar {
	return &ScalarK256{
		value: new(big.Int).Exp(s.value, big.NewInt(2), btcec.S256().N),
	}
}

func (s *ScalarK256) Double() Scalar {
	v := new(big.Int).Add(s.value, s.value)
	return &ScalarK256{
		value: v.Mod(v, btcec.S256().N),
	}
}

func (s *ScalarK256) Invert() (Scalar, error) {
	return &ScalarK256{
		value: new(big.Int).ModInverse(s.value, btcec.S256().N),
	}, nil
}

func (s *ScalarK256) Sqrt() (Scalar, error) {
	return &ScalarK256{
		value: new(big.Int).ModSqrt(s.value, btcec.S256().N),
	}, nil
}

func (s *ScalarK256) Cube() Scalar {
	return &ScalarK256{
		value: new(big.Int).Exp(s.value, big.NewInt(3), btcec.S256().N),
	}
}

func (s *ScalarK256) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		v := new(big.Int).Add(s.value, r.value)
		return &ScalarK256{
			value: v.Mod(v, btcec.S256().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarK256) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		v := new(big.Int).Sub(s.value, r.value)
		return &ScalarK256{
			value: v.Mod(v, btcec.S256().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarK256) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		v := new(big.Int).Mul(s.value, r.value)
		return &ScalarK256{
			value: v.Mod(v, btcec.S256().N),
		}
	} else {
		return nil
	}
}

func (s *ScalarK256) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarK256) Div(rhs Scalar) Scalar {
	n := btcec.S256().N
	r, ok := rhs.(*ScalarK256)
	if ok {
		v := new(big.Int).ModInverse(r.value, n)
		v.Mul(v, s.value)
		return &ScalarK256{
			value: v.Mod(v, n),
		}
	} else {
		return nil
	}
}

func (s *ScalarK256) Neg() Scalar {
	z := new(big.Int).Neg(s.value)
	return &ScalarK256{
		value: z.Mod(z, btcec.S256().N),
	}
}

func (s *ScalarK256) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := new(big.Int).Mod(v, btcec.S256().N)
	if t.Cmp(v) != 0 {
		return nil, fmt.Errorf("invalid value")
	}
	return &ScalarK256{
		value: t,
	}, nil
}

func (s *ScalarK256) BigInt() *big.Int {
	return new(big.Int).Set(s.value)
}

func (s *ScalarK256) Bytes() []byte {
	var out [32]byte
	return s.value.FillBytes(out[:])
}

func (s *ScalarK256) SetBytes(bytes []byte) (Scalar, error) {
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, btcec.S256().N)
	if t.Cmp(value) != 0 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	return &ScalarK256{
		value: t,
	}, nil
}

func (s *ScalarK256) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) < 32 || len(bytes) > 128 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := new(big.Int).SetBytes(bytes)
	value.Mod(value, btcec.S256().N)
	return &ScalarK256{
		value,
	}, nil
}

func (s *ScalarK256) Point() Point {
	return new(PointK256).Identity()
}

func (s *ScalarK256) Clone() Scalar {
	return &ScalarK256{
		value: new(big.Int).Set(s.value),
	}
}

func (s *ScalarK256) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarK256) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarK256) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarK256) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarK256) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarK256) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*ScalarK256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *PointK256) Random(reader io.Reader) Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointK256) Hash(bytes []byte) Point {
	curve := btcec.S256()

	var domain = []byte("secp256k1_XMD:SHA-256_SSWU_RO_")
	uniformBytes, _ := expandMsgXmd(sha256.New(), bytes, domain, 96)

	u0 := new(big.Int).SetBytes(uniformBytes[:48])
	u1 := new(big.Int).SetBytes(uniformBytes[48:])

	u0.Mod(u0, curve.P)
	u1.Mod(u1, curve.P)

	ssParams := k256SswuParams()
	r0x, r0y := osswu3mod4(u0, ssParams)
	r1x, r1y := osswu3mod4(u1, ssParams)

	isoParams := k256IsogenyParams()
	q0x, q0y := isogenyMap(r0x, r0y, isoParams)
	q1x, q1y := isogenyMap(r1x, r1y, isoParams)

	x, y := curve.Add(q0x, q0y, q1x, q1y)
	return &PointK256{
		x, y,
	}
}

func (p *PointK256) Identity() Point {
	return &PointK256{
		x: big.NewInt(0), y: big.NewInt(0),
	}
}

func (p *PointK256) Generator() Point {
	curve := btcec.S256()
	return &PointK256{
		x: new(big.Int).Set(curve.Gx),
		y: new(big.Int).Set(curve.Gy),
	}
}

func (p *PointK256) IsIdentity() bool {
	x := core.ConstantTimeEqByte(p.x, core.Zero)
	y := core.ConstantTimeEqByte(p.y, core.Zero)
	return (x & y) == 1
}

func (p *PointK256) IsNegative() bool {
	return p.y.Bit(0) == 1
}

func (p *PointK256) IsOnCurve() bool {
	return btcec.S256().IsOnCurve(p.x, p.y)
}

func (p *PointK256) Double() Point {
	x, y := btcec.S256().Double(p.x, p.y)
	return &PointK256{x, y}
}

func (p *PointK256) Scalar() Scalar {
	return new(ScalarK256).Zero()
}

func (p *PointK256) Neg() Point {
	y := new(big.Int).Sub(btcec.S256().P, p.y)
	y.Mod(y, btcec.S256().P)
	return &PointK256{x: p.x, y: y}
}

func (p *PointK256) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointK256)
	if ok {
		x, y := btcec.S256().Add(p.x, p.y, r.x, r.y)
		return &PointK256{x, y}
	} else {
		return nil
	}
}

func (p *PointK256) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.Neg().(*PointK256)
	if ok {
		x, y := btcec.S256().Add(p.x, p.y, r.x, r.y)
		return &PointK256{x, y}
	} else {
		return nil
	}
}

func (p *PointK256) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarK256)
	if ok {
		x, y := btcec.S256().ScalarMult(p.x, p.y, r.value.Bytes())
		return &PointK256{x, y}
	} else {
		return nil
	}
}

func (p *PointK256) Equal(rhs Point) bool {
	r, ok := rhs.(*PointK256)
	if ok {
		x := core.ConstantTimeEqByte(p.x, r.x)
		y := core.ConstantTimeEqByte(p.y, r.y)
		return (x & y) == 1
	} else {
		return false
	}
}

func (p *PointK256) Set(x, y *big.Int) (Point, error) {
	// check is identity or on curve
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	// Checks are constant time
	onCurve := btcec.S256().IsOnCurve(x, y)
	if !onCurve && (xx&yy) != 1 {
		return nil, fmt.Errorf("invalid coordinates")
	}
	x = new(big.Int).Set(x)
	y = new(big.Int).Set(y)
	return &PointK256{x, y}, nil
}

func (p *PointK256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)
	x[0] |= byte(p.y.Bit(0))
	p.x.FillBytes(x[1:])
	return x[:]
}

func (p *PointK256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out[:]
}

func (p *PointK256) FromAffineCompressed(bytes []byte) (Point, error) {
	if len(bytes) != 33 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sign := int(bytes[0])
	if sign != 2 && sign != 3 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	sign &= 0x1

	x := new(big.Int).SetBytes(bytes[1:])
	rhs := rhsK256(x, btcec.S256().Params())
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y := new(big.Int).ModSqrt(rhs, btcec.S256().P)
	if y != nil {
		// fix the sign
		if int(y.Bit(0)) != sign {
			y.Neg(y)
			y.Mod(y, btcec.S256().P)
		}
	} else {
		x = new(big.Int)
		y = new(big.Int)
	}
	return &PointK256{
		x, y,
	}, nil
}

func (p *PointK256) FromAffineUncompressed(bytes []byte) (Point, error) {
	if len(bytes) != 65 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	if bytes[0] != 4 {
		return nil, fmt.Errorf("invalid sign byte")
	}
	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:])
	return &PointK256{x, y}, nil
}

func (p *PointK256) CurveName() string {
	return btcec.S256().Name
}

func (p *PointK256) SumOfProducts(points []Point, scalars []Scalar) Point {
	nScalars := make([]*big.Int, len(scalars))
	for i, sc := range scalars {
		s, ok := sc.(*ScalarK256)
		if !ok {
			return nil
		}
		nScalars[i] = s.value
	}
	return sumOfProductsPippenger(points, nScalars)
}

func (p *PointK256) X() *big.Int {
	return new(big.Int).Set(p.x)
}

func (p *PointK256) Y() *big.Int {
	return new(big.Int).Set(p.y)
}

func (p *PointK256) Params() *elliptic.CurveParams {
	return btcec.S256().Params()
}

func (p *PointK256) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointK256) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *PointK256) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointK256) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.x = ppt.x
	p.y = ppt.y
	return nil
}

func (p *PointK256) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointK256) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointK256)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.x = P.x
	p.y = P.y
	return nil
}

// rhs of the curve equation
func rhsK256(x *big.Int, params *elliptic.CurveParams) *big.Int {
	f := NewField(params.P)
	r := f.NewElement(x)
	r2 := r.Mul(r)

	// x^3+Ax+B
	// A = 0 for secp256k1
	// Just add B
	r = r2.Mul(r)
	return r.Add(f.NewElement(params.B)).Value
}

// Taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-E.1
func k256IsogenyParams() *isogenyParams {
	return &isogenyParams{
		P: btcec.S256().P,
		Xnum: []*big.Int{
			bhex("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7"),
			bhex("07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581"),
			bhex("534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262"),
			bhex("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c"),
		},
		Xden: []*big.Int{
			bhex("d35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b"),
			bhex("edadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14"),
			bhex("0000000000000000000000000000000000000000000000000000000000000001"),
		},
		Ynum: []*big.Int{
			bhex("4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c"),
			bhex("c75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3"),
			bhex("29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931"),
			bhex("2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84"),
		},
		Yden: []*big.Int{
			bhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b"),
			bhex("7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573"),
			bhex("6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f"),
			bhex("0000000000000000000000000000000000000000000000000000000000000001"),
		},
	}
}

// Take from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.7
func k256SswuParams() *sswuParams {
	params := btcec.S256().Params()

	// c1 = (q - 3) / 4
	c1 := new(big.Int).Set(params.P)
	c1.Sub(c1, big.NewInt(3))
	c1.Rsh(c1, 2)

	a, _ := new(big.Int).SetString("3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 16)
	b := big.NewInt(1771)
	z := big.NewInt(-11)
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
