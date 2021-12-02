//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"sync"

	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
)

const g1pointSize = 48

var bls12381g1Initonce sync.Once
var bls12381g1 Bls12381G1Curve

var g1 = bls12381.NewG1()

type Bls12381G1Curve struct {
	*elliptic.CurveParams
}

func bls12381g1InitAll() {
	bls12381g1.CurveParams = new(elliptic.CurveParams)
	bls12381g1.P, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
	bls12381g1.N = g1.Q()
	bls12381g1.B, _ = new(big.Int).SetString("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271", 16)
	bls12381g1.Gx, _ = new(big.Int).SetString("120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16", 16)
	bls12381g1.Gy, _ = new(big.Int).SetString("0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271", 16)
	bls12381g1.BitSize = 381
	bls12381g1.Name = "Bls12381G1"
}

func Bls12381G1() *Bls12381G1Curve {
	bls12381g1Initonce.Do(bls12381g1InitAll)
	return &bls12381g1
}

func bigIntCoordsToPointG1(x, y *big.Int, pointSize int) (*bls12381.PointG1, error) {
	arr := make([]byte, pointSize*2)
	mid := pointSize
	// Use big-endian format copy from the back
	b := x.Bytes()
	i := mid - 1
	for j := len(b) - 1; j >= 0; j-- {
		arr[i] = b[j]
		i--
	}

	b = y.Bytes()
	i = len(arr) - 1
	for j := len(b) - 1; j >= 0; j-- {
		arr[i] = b[j]
		i--
	}
	return g1.FromUncompressed(arr)
}

func pointG1ToBigIntCoords(p *bls12381.PointG1, pointSize int) (*big.Int, *big.Int) {
	b, _ := g1.ToUncompressed(p)
	x := new(big.Int).SetBytes(b[:pointSize])
	y := new(big.Int).SetBytes(b[pointSize:])
	return x, y
}

func (curve *Bls12381G1Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve *Bls12381G1Curve) IsOnCurve(x, y *big.Int) bool {
	_, err := bigIntCoordsToPointG1(x, y, g1pointSize)
	return err == nil
}

func (curve *Bls12381G1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := bigIntCoordsToPointG1(x1, y1, g1pointSize)
	if err != nil {
		panic(err)
	}
	p2, err := bigIntCoordsToPointG1(x2, y2, g1pointSize)
	if err != nil {
		panic(err)
	}
	g1.Add(p1, p1, p2)

	return pointG1ToBigIntCoords(p1, g1pointSize)
}

func (curve *Bls12381G1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := bigIntCoordsToPointG1(x1, y1, g1pointSize)
	if err != nil {
		panic(err)
	}
	g1.Double(p, p)
	return pointG1ToBigIntCoords(p, g1pointSize)
}

func (curve *Bls12381G1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p, err := bigIntCoordsToPointG1(Bx, By, g1pointSize)
	if err != nil {
		panic(err)
	}
	s := new(big.Int).SetBytes(k)
	g1.MulScalar(p, p, s)
	if !g1.InCorrectSubgroup(p) {
		panic("point is not in correct subgroup")
	}
	return pointG1ToBigIntCoords(p, g1pointSize)
}

func (curve *Bls12381G1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	s := new(big.Int).SetBytes(k)
	p := g1.New()
	g1.MulScalar(p, g1.One(), s)
	if !g1.InCorrectSubgroup(p) {
		panic("point is not in correct subgroup")
	}
	return pointG1ToBigIntCoords(p, g1pointSize)
}

// Hash an arbitrary byte sequence to a G1 point according to the hash-to-curve standard
func (curve *Bls12381G1Curve) Hash(msg []byte) (*big.Int, *big.Int) {
	p, err := g1.HashToCurve(sha256.New, msg, []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_"))
	if err != nil {
		panic(err)
	}
	return pointG1ToBigIntCoords(p, g1pointSize)
}

// CompressedBytesFromBigInts takes x and y coordinates and converts them to the BLS compressed point form
func (curve *Bls12381G1Curve) CompressedBytesFromBigInts(x, y *big.Int) ([]byte, error) {
	p, err := bigIntCoordsToPointG1(x, y, g1pointSize)
	if err != nil {
		return nil, err
	}
	return g1.ToCompressed(p), nil
}
