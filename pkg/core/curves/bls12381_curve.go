//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// NOTE that the bls curves are NOT constant time. There is an open issue to address it: https://github.com/coinbase/kryptology/issues/44


package curves

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core"
	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
	cc20rand "github.com/nixberg/chacha-rng-go"
	"io"
	"math/big"
)

var g1 = bls12381.NewG1()
var g2 = bls12381.NewG2()
var gt = bls12381.NewEngine().GT()
var bls12381modulus = bhex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")

type ScalarBls12381 struct {
	Value *big.Int
	point Point
}

type PointBls12381G1 struct {
	Value *bls12381.PointG1
}

type PointBls12381G2 struct {
	Value *bls12381.PointG2
}

type ScalarBls12381Gt struct {
	Value *bls12381.E
}

func (s *ScalarBls12381) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarBls12381) Hash(bytes []byte) Scalar {
	xmd, err := expandMsgXmd(sha256.New(), bytes, []byte("BLS12381_XMD:SHA-256_SSWU_RO_"), 48)
	if err != nil {
		return nil
	}
	v := new(big.Int).SetBytes(xmd)
	return &ScalarBls12381{
		Value: v.Mod(v, g1.Q()),
		point: s.point,
	}
}

func (s *ScalarBls12381) Zero() Scalar {
	return &ScalarBls12381{
		Value: big.NewInt(0),
		point: s.point,
	}
}

func (s *ScalarBls12381) One() Scalar {
	return &ScalarBls12381{
		Value: big.NewInt(1),
		point: s.point,
	}
}

func (s *ScalarBls12381) IsZero() bool {
	return subtle.ConstantTimeCompare(s.Value.Bytes(), []byte{}) == 1
}

func (s *ScalarBls12381) IsOne() bool {
	return subtle.ConstantTimeCompare(s.Value.Bytes(), []byte{1}) == 1
}

func (s *ScalarBls12381) IsOdd() bool {
	return s.Value.Bit(0) == 1
}

func (s *ScalarBls12381) IsEven() bool {
	return s.Value.Bit(0) == 0
}

func (s *ScalarBls12381) New(value int) Scalar {
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, g1.Q())
	}
	return &ScalarBls12381{
		Value: v,
		point: s.point,
	}
}

func (s *ScalarBls12381) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		return -2
	}
}

func (s *ScalarBls12381) Square() Scalar {
	return &ScalarBls12381{
		Value: new(big.Int).Exp(s.Value, big.NewInt(2), g1.Q()),
		point: s.point,
	}
}

func (s *ScalarBls12381) Double() Scalar {
	v := new(big.Int).Add(s.Value, s.Value)
	return &ScalarBls12381{
		Value: v.Mod(v, g1.Q()),
		point: s.point,
	}
}

func (s *ScalarBls12381) Invert() (Scalar, error) {
	return &ScalarBls12381{
		Value: new(big.Int).ModInverse(s.Value, g1.Q()),
		point: s.point,
	}, nil
}

func (s *ScalarBls12381) Sqrt() (Scalar, error) {
	return &ScalarBls12381{
		Value: new(big.Int).ModSqrt(s.Value, g1.Q()),
		point: s.point,
	}, nil
}

func (s *ScalarBls12381) Cube() Scalar {
	return &ScalarBls12381{
		Value: new(big.Int).Exp(s.Value, big.NewInt(3), g1.Q()),
		point: s.point,
	}
}

func (s *ScalarBls12381) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		v := new(big.Int).Add(s.Value, r.Value)
		return &ScalarBls12381{
			Value: v.Mod(v, g1.Q()),
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		v := new(big.Int).Sub(s.Value, r.Value)
		return &ScalarBls12381{
			Value: v.Mod(v, g1.Q()),
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		v := new(big.Int).Mul(s.Value, r.Value)
		return &ScalarBls12381{
			Value: v.Mod(v, g1.Q()),
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarBls12381) Div(rhs Scalar) Scalar {
	n := g1.Q()
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		v := new(big.Int).ModInverse(r.Value, n)
		v.Mul(v, s.Value)
		return &ScalarBls12381{
			Value: v.Mod(v, n),
			point: s.point,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381) Neg() Scalar {
	z := new(big.Int).Neg(s.Value)
	return &ScalarBls12381{
		Value: z.Mod(z, g1.Q()),
		point: s.point,
	}
}

func (s *ScalarBls12381) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid value")
	}
	t := new(big.Int).Mod(v, g1.Q())
	if t.Cmp(v) != 0 {
		return nil, fmt.Errorf("invalid value")
	}
	return &ScalarBls12381{
		Value: t,
		point: s.point,
	}, nil
}

func (s *ScalarBls12381) BigInt() *big.Int {
	return new(big.Int).Set(s.Value)
}

func (s *ScalarBls12381) Bytes() []byte {
	var out [32]byte
	return s.Value.FillBytes(out[:])
}

func (s *ScalarBls12381) SetBytes(bytes []byte) (Scalar, error) {
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, g1.Q())
	if t.Cmp(value) != 0 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	return &ScalarBls12381{
		Value: t,
		point: s.point,
	}, nil
}

func (s *ScalarBls12381) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) < 32 || len(bytes) > 128 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := new(big.Int).SetBytes(bytes)
	t := new(big.Int).Mod(value, g1.Q())
	return &ScalarBls12381{
		Value: t,
		point: s.point,
	}, nil
}

func (s *ScalarBls12381) Point() Point {
	return s.point.Identity()
}

func (s *ScalarBls12381) Clone() Scalar {
	return &ScalarBls12381{
		Value: new(big.Int).Set(s.Value),
		point: s.point,
	}
}

func (s *ScalarBls12381) SetPoint(p Point) PairingScalar {
	return &ScalarBls12381{
		Value: new(big.Int).Set(s.Value),
		point: p,
	}
}

func (s *ScalarBls12381) Order() *big.Int {
	return g1.Q()
}

func (s *ScalarBls12381) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarBls12381) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls12381)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	s.point = ss.point
	return nil
}

func (s *ScalarBls12381) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarBls12381) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls12381)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	s.point = ss.point
	return nil
}

func (s *ScalarBls12381) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarBls12381) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*ScalarBls12381)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.Value = S.Value
	return nil
}

func (p *PointBls12381G1) Random(reader io.Reader) Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointBls12381G1) Hash(bytes []byte) Point {
	var domain = []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_")
	pt, err := g1.HashToCurve(sha256.New, bytes, domain)
	if err != nil {
		return nil
	}
	return &PointBls12381G1{Value: pt}
}

func (p *PointBls12381G1) Identity() Point {
	return &PointBls12381G1{
		Value: g1.New(),
	}
}

func (p *PointBls12381G1) Generator() Point {
	return &PointBls12381G1{
		Value: g1.One(),
	}
}

func (p *PointBls12381G1) IsIdentity() bool {
	return g1.IsZero(p.Value)
}

func (p *PointBls12381G1) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (g1.ToCompressed(p.Value)[0]>>5)&1 == 1
}

func (p *PointBls12381G1) IsOnCurve() bool {
	return g1.IsOnCurve(p.Value)
}

func (p *PointBls12381G1) Double() Point {
	value := g1.Double(g1.New(), p.Value)
	return &PointBls12381G1{value}
}

func (p *PointBls12381G1) Scalar() Scalar {
	return &ScalarBls12381{
		Value: new(big.Int),
		point: new(PointBls12381G1),
	}
}

func (p *PointBls12381G1) Neg() Point {
	value := g1.Neg(g1.New(), p.Value)
	return &PointBls12381G1{value}
}

func (p *PointBls12381G1) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls12381G1)
	if ok {
		value := g1.Add(g1.New(), p.Value, r.Value)
		return &PointBls12381G1{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G1) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls12381G1)
	if ok {
		value := g1.Sub(g1.New(), p.Value, r.Value)
		return &PointBls12381G1{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G1) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		value := g1.MulScalar(g1.New(), p.Value, r.Value)
		return &PointBls12381G1{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G1) Equal(rhs Point) bool {
	r, ok := rhs.(*PointBls12381G1)
	if ok {
		return g1.Equal(p.Value, r.Value)
	} else {
		return false
	}
}

func (p *PointBls12381G1) Set(x, y *big.Int) (Point, error) {
	if x.Cmp(core.Zero) == 0 &&
		y.Cmp(core.Zero) == 0 {
		return p.Identity(), nil
	}
	var data [96]byte
	x.FillBytes(data[:48])
	y.FillBytes(data[48:])
	value, err := g1.FromUncompressed(data[:])
	if err != nil {
		return nil, fmt.Errorf("invalid coordinates")
	}
	return &PointBls12381G1{value}, nil
}

func (p *PointBls12381G1) ToAffineCompressed() []byte {
	return g1.ToCompressed(p.Value)
}

func (p *PointBls12381G1) ToAffineUncompressed() []byte {
	bytes, err := g1.ToUncompressed(p.Value)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (p *PointBls12381G1) FromAffineCompressed(bytes []byte) (Point, error) {
	value, err := g1.FromCompressed(bytes)
	if err != nil {
		return nil, err
	}
	return &PointBls12381G1{value}, nil
}

func (p *PointBls12381G1) FromAffineUncompressed(bytes []byte) (Point, error) {
	value, err := g1.FromUncompressed(bytes)
	if err != nil {
		return nil, err
	}
	return &PointBls12381G1{value}, nil
}

func (p *PointBls12381G1) CurveName() string {
	return "BLS12381G1"
}

func (p *PointBls12381G1) SumOfProducts(points []Point, scalars []Scalar) Point {
	nPoints := make([]*bls12381.PointG1, len(points))
	nScalars := make([]*big.Int, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointBls12381G1)
		if !ok {
			return nil
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarBls12381)
		if !ok {
			return nil
		}
		nScalars[i] = s.Value
	}
	value := g1.New()
	_, err := g1.MultiExp(value, nPoints, nScalars)
	if err != nil {
		return nil
	}
	return &PointBls12381G1{value}
}

func (p *PointBls12381G1) OtherGroup() PairingPoint {
	return new(PointBls12381G2).Identity().(PairingPoint)
}

func (p *PointBls12381G1) Pairing(rhs PairingPoint) Scalar {
	var err error
	pt, ok := rhs.(*PointBls12381G2)
	if !ok {
		return nil
	}
	if !g1.InCorrectSubgroup(p.Value) ||
		!g2.InCorrectSubgroup(pt.Value) {
		return nil
	}
	value := &bls12381.E{}
	if g1.IsZero(p.Value) || g2.IsZero(pt.Value) {
		return &ScalarBls12381Gt{value}
	}
	eng := bls12381.NewEngine()
	eng.AddPair(p.Value, pt.Value)

	value, err = eng.Result()
	if err != nil {
		panic(err)
	}

	return &ScalarBls12381Gt{value}
}

func (p *PointBls12381G1) MultiPairing(points ...PairingPoint) Scalar {
	return multiPairing(points...)
}

func (p *PointBls12381G1) X() *big.Int {
	bytes := g1.ToBytes(p.Value)
	return new(big.Int).SetBytes(bytes[:48])
}

func (p *PointBls12381G1) Y() *big.Int {
	bytes := g1.ToBytes(p.Value)
	return new(big.Int).SetBytes(bytes[48:])
}

func (p *PointBls12381G1) Modulus() *big.Int {
	return bls12381modulus
}

func (p *PointBls12381G1) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointBls12381G1) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls12381G1)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls12381G1) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointBls12381G1) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls12381G1)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls12381G1) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointBls12381G1) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointBls12381G1)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.Value = P.Value
	return nil
}

func (p *PointBls12381G2) Random(reader io.Reader) Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointBls12381G2) Hash(bytes []byte) Point {
	var domain = []byte("BLS12381G2_XMD:SHA-256_SSWU_RO_")
	pt, err := g2.HashToCurve(sha256.New, bytes, domain)
	if err != nil {
		return nil
	}
	return &PointBls12381G2{Value: pt}
}

func (p *PointBls12381G2) Identity() Point {
	return &PointBls12381G2{
		Value: g2.New(),
	}
}

func (p *PointBls12381G2) Generator() Point {
	return &PointBls12381G2{
		Value: g2.One(),
	}
}

func (p *PointBls12381G2) IsIdentity() bool {
	return g2.IsZero(p.Value)
}

func (p *PointBls12381G2) IsNegative() bool {
	// According to https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#serialization
	// This bit represents the sign of the `y` coordinate which is what we want
	return (g2.ToCompressed(p.Value)[0]>>5)&1 == 1
}

func (p *PointBls12381G2) IsOnCurve() bool {
	return g2.IsOnCurve(p.Value)
}

func (p *PointBls12381G2) Double() Point {
	value := g2.Double(g2.New(), p.Value)
	return &PointBls12381G2{value}
}

func (p *PointBls12381G2) Scalar() Scalar {
	return &ScalarBls12381{
		Value: new(big.Int),
		point: new(PointBls12381G2),
	}
}

func (p *PointBls12381G2) Neg() Point {
	value := g2.Neg(g2.New(), p.Value)
	return &PointBls12381G2{value}
}

func (p *PointBls12381G2) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls12381G2)
	if ok {
		value := g2.Add(g2.New(), p.Value, r.Value)
		return &PointBls12381G2{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G2) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointBls12381G2)
	if ok {
		value := g2.Sub(g2.New(), p.Value, r.Value)
		return &PointBls12381G2{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G2) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		value := g2.MulScalar(g2.New(), p.Value, r.Value)
		return &PointBls12381G2{value}
	} else {
		return nil
	}
}

func (p *PointBls12381G2) Equal(rhs Point) bool {
	r, ok := rhs.(*PointBls12381G2)
	if ok {
		return g2.Equal(p.Value, r.Value)
	} else {
		return false
	}
}

func (p *PointBls12381G2) Set(x, y *big.Int) (Point, error) {
	if x.Cmp(core.Zero) == 0 &&
		y.Cmp(core.Zero) == 0 {
		return p.Identity(), nil
	}
	var data [192]byte
	x.FillBytes(data[:96])
	y.FillBytes(data[96:])
	value, err := g2.FromUncompressed(data[:])
	if err != nil {
		return nil, fmt.Errorf("invalid coordinates")
	}
	return &PointBls12381G2{value}, nil
}

func (p *PointBls12381G2) ToAffineCompressed() []byte {
	return g2.ToCompressed(p.Value)
}

func (p *PointBls12381G2) ToAffineUncompressed() []byte {
	bytes, err := g2.ToUncompressed(p.Value)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (p *PointBls12381G2) FromAffineCompressed(bytes []byte) (Point, error) {
	value, err := g2.FromCompressed(bytes)
	if err != nil {
		return nil, err
	}
	return &PointBls12381G2{value}, nil
}

func (p *PointBls12381G2) FromAffineUncompressed(bytes []byte) (Point, error) {
	value, err := g2.FromUncompressed(bytes)
	if err != nil {
		return nil, err
	}
	return &PointBls12381G2{value}, nil
}

func (p *PointBls12381G2) CurveName() string {
	return "BLS12381G2"
}

func (p *PointBls12381G2) SumOfProducts(points []Point, scalars []Scalar) Point {
	nPoints := make([]*bls12381.PointG2, len(points))
	nScalars := make([]*big.Int, len(scalars))
	for i, pt := range points {
		pp, ok := pt.(*PointBls12381G2)
		if !ok {
			return nil
		}
		nPoints[i] = pp.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarBls12381)
		if !ok {
			return nil
		}
		nScalars[i] = s.Value
	}
	value := g2.New()
	_, err := g2.MultiExp(value, nPoints, nScalars)
	if err != nil {
		return nil
	}
	return &PointBls12381G2{value}
}

func (p *PointBls12381G2) OtherGroup() PairingPoint {
	return new(PointBls12381G1).Identity().(PairingPoint)
}

func (p *PointBls12381G2) Pairing(rhs PairingPoint) Scalar {
	var err error
	pt, ok := rhs.(*PointBls12381G1)
	if !ok {
		return nil
	}
	if !g2.InCorrectSubgroup(p.Value) ||
		!g1.InCorrectSubgroup(pt.Value) {
		return nil
	}
	value := &bls12381.E{}
	if g2.IsZero(p.Value) || g1.IsZero(pt.Value) {
		return &ScalarBls12381Gt{value}
	}
	eng := bls12381.NewEngine()
	eng.AddPair(pt.Value, p.Value)

	value, err = eng.Result()
	if err != nil {
		panic(err)
	}

	return &ScalarBls12381Gt{value}
}

func (p *PointBls12381G2) MultiPairing(points ...PairingPoint) Scalar {
	return multiPairing(points...)
}

func (p *PointBls12381G2) X() *big.Int {
	bytes := g2.ToBytes(p.Value)
	return new(big.Int).SetBytes(bytes[:96])
}

func (p *PointBls12381G2) Y() *big.Int {
	bytes := g2.ToBytes(p.Value)
	return new(big.Int).SetBytes(bytes[96:])
}

func (p *PointBls12381G2) Modulus() *big.Int {
	return bls12381modulus
}

func (p *PointBls12381G2) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointBls12381G2) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls12381G2)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls12381G2) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointBls12381G2) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointBls12381G2)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointBls12381G2) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointBls12381G2) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointBls12381G2)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.Value = P.Value
	return nil
}

func multiPairing(points ...PairingPoint) Scalar {
	if len(points)%2 != 0 {
		return nil
	}
	valid := true
	eng := bls12381.NewEngine()
	for i := 0; i < len(points); i += 2 {
		pt1, ok := points[i].(*PointBls12381G1)
		valid = valid && ok
		pt2, ok := points[i+1].(*PointBls12381G2)
		valid = valid && ok
		if valid {
			valid = valid && g1.InCorrectSubgroup(pt1.Value)
			valid = valid && g2.InCorrectSubgroup(pt2.Value)
		}
		if valid {
			eng.AddPair(pt1.Value, pt2.Value)
		}
	}
	if !valid {
		return nil
	}

	value, err := eng.Result()
	if err != nil {
		panic(err)
	}

	return &ScalarBls12381Gt{value}
}

func (s *ScalarBls12381Gt) Random(reader io.Reader) Scalar {
	const width = 48
	offset := 0
	var data [576]byte
	for i := 0; i < 12; i++ {
		tv, err := rand.Int(reader, bls12381modulus)
		if err != nil {
			return nil
		}
		tv.FillBytes(data[offset*width : (offset+1)*width])
		offset++
	}
	value, err := gt.FromBytes(data[:])
	if err != nil {
		return nil
	}
	return &ScalarBls12381Gt{value}
}

func (s *ScalarBls12381Gt) Hash(bytes []byte) Scalar {
	reader := new(chachaReader)
	err := reader.Seed(bytes)
	if err != nil {
		return nil
	}
	return s.Random(reader)
}

type chachaReader struct {
	rng *cc20rand.ChaCha
}

func (cc20 *chachaReader) Seed(bytes []byte) error {
	var seed [8]uint32
	output, err := core.FiatShamir(new(big.Int).SetBytes(bytes))
	if err != nil {
		return err
	}
	j := 0
	for i := 0; i < len(output); i += 4 {
		seed[j] = uint32(output[i]) << 24
		seed[j] |= uint32(output[i+1]) << 16
		seed[j] |= uint32(output[i+2]) << 8
		seed[j] |= uint32(output[i+2])
	}
	cc20.rng = cc20rand.Seeded20(seed, 0)
	return nil
}

func (cc20 *chachaReader) Read(bytes []byte) (n int, err error) {
	cc20.rng.FillUint8(bytes)
	n = 0
	err = nil
	return
}

func (s *ScalarBls12381Gt) Zero() Scalar {
	return &ScalarBls12381Gt{gt.New()}
}

func (s *ScalarBls12381Gt) One() Scalar {
	return &ScalarBls12381Gt{gt.New().One()}
}

func (s *ScalarBls12381Gt) IsZero() bool {
	return s.Value.Equal(gt.New())
}

func (s *ScalarBls12381Gt) IsOne() bool {
	return s.Value.IsOne()
}

func (s *ScalarBls12381Gt) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarBls12381Gt) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls12381Gt)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarBls12381Gt) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarBls12381Gt) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarBls12381Gt)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarBls12381Gt) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarBls12381Gt) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*ScalarBls12381Gt)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.Value = S.Value
	return nil
}

func (s *ScalarBls12381Gt) IsOdd() bool {
	data := gt.ToBytes(s.Value)
	return data[0]&1 == 1
}

func (s *ScalarBls12381Gt) IsEven() bool {
	data := gt.ToBytes(s.Value)
	return data[0]&1 == 0
}

func (s *ScalarBls12381Gt) New(input int) Scalar {
	var data [576]byte
	data[3] = byte(input >> 24 & 0xFF)
	data[2] = byte(input >> 16 & 0xFF)
	data[1] = byte(input >> 8 & 0xFF)
	data[0] = byte(input & 0xFF)

	value, err := gt.FromBytes(data[:])
	if err != nil {
		return nil
	}
	return &ScalarBls12381Gt{value}
}

func (s *ScalarBls12381Gt) Cmp(rhs Scalar) int {
	r, ok := rhs.(*ScalarBls12381Gt)
	if ok && s.Value.Equal(r.Value) {
		return 0
	} else {
		return -2
	}
}

func (s *ScalarBls12381Gt) Square() Scalar {
	value := gt.New()
	gt.Square(value, s.Value)
	return &ScalarBls12381Gt{
		value,
	}
}

func (s *ScalarBls12381Gt) Double() Scalar {
	value := gt.New()
	gt.Add(value, s.Value, s.Value)
	return &ScalarBls12381Gt{
		value,
	}
}

func (s *ScalarBls12381Gt) Invert() (Scalar, error) {
	value := gt.New()
	gt.Inverse(value, s.Value)
	return &ScalarBls12381Gt{
		value,
	}, nil
}

func (s *ScalarBls12381Gt) Sqrt() (Scalar, error) {
	// Not implemented
	return nil, nil
}

func (s *ScalarBls12381Gt) Cube() Scalar {
	value := gt.New()
	gt.Square(value, s.Value)
	gt.Mul(value, value, s.Value)
	return &ScalarBls12381Gt{
		value,
	}
}

func (s *ScalarBls12381Gt) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381Gt)
	if ok {
		value := gt.New()
		gt.Add(value, s.Value, r.Value)
		return &ScalarBls12381Gt{
			value,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381Gt) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381Gt)
	if ok {
		value := gt.New()
		gt.Sub(value, s.Value, r.Value)
		return &ScalarBls12381Gt{
			value,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381Gt) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381Gt)
	if ok {
		value := gt.New()
		gt.Mul(value, s.Value, r.Value)
		return &ScalarBls12381Gt{
			value,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381Gt) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarBls12381Gt) Div(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarBls12381Gt)
	if ok {
		value := gt.New()
		gt.Inverse(value, r.Value)
		gt.Mul(value, value, s.Value)
		return &ScalarBls12381Gt{
			value,
		}
	} else {
		return nil
	}
}

func (s *ScalarBls12381Gt) Neg() Scalar {
	value := gt.New()
	gt.Sub(value, value, s.Value)
	return &ScalarBls12381Gt{
		value,
	}
}

func (s *ScalarBls12381Gt) SetBigInt(v *big.Int) (Scalar, error) {
	var bytes [576]byte
	v.FillBytes(bytes[:])
	return s.SetBytes(bytes[:])
}

func (s *ScalarBls12381Gt) BigInt() *big.Int {
	return new(big.Int).SetBytes(gt.ToBytes(s.Value))
}

func (s *ScalarBls12381Gt) Point() Point {
	return &PointBls12381G1{Value: g1.New()}
}

func (s *ScalarBls12381Gt) Bytes() []byte {
	return gt.ToBytes(s.Value)
}

func (s *ScalarBls12381Gt) SetBytes(bytes []byte) (Scalar, error) {
	value, err := gt.FromBytes(bytes)
	if err != nil {
		return nil, err
	}
	return &ScalarBls12381Gt{value}, nil
}

func (s *ScalarBls12381Gt) SetBytesWide(bytes []byte) (Scalar, error) {
	l := len(bytes)
	if l != 1152 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value, err := gt.FromBytes(bytes[:l/2])
	if err != nil {
		return nil, err
	}
	value2, err := gt.FromBytes(bytes[l/2:])
	if err != nil {
		return nil, err
	}
	gt.Add(value, value2, value)
	return &ScalarBls12381Gt{value}, nil
}

func (s *ScalarBls12381Gt) Clone() Scalar {
	return &ScalarBls12381Gt{
		Value: gt.New().Set(s.Value),
	}
}
