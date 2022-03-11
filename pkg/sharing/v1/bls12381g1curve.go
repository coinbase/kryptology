//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
)

var bls12381g1Initonce sync.Once
var bls12381g1 Bls12381G1Curve

type Bls12381G1Curve struct {
	*elliptic.CurveParams
}

func bls12381g1InitAll() {
	bls12381g1.CurveParams = new(elliptic.CurveParams)
	bls12381g1.P, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
	bls12381g1.N = bls12381.Bls12381FqNew().Params.BiModulus
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

func (curve *Bls12381G1Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve *Bls12381G1Curve) IsOnCurve(x, y *big.Int) bool {
	_, err := new(bls12381.G1).SetBigInt(x, y)
	return err == nil
}

func (curve *Bls12381G1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err1 := new(bls12381.G1).SetBigInt(x1, y1)
	p2, err2 := new(bls12381.G1).SetBigInt(x2, y2)

	if err1 != nil || err2 != nil {
		return nil, nil
	}
	return p1.Add(p1, p2).BigInt()
}

func (curve *Bls12381G1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := new(bls12381.G1).SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	return p.Double(p).BigInt()
}

func (curve *Bls12381G1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p, err := new(bls12381.G1).SetBigInt(Bx, By)
	if err != nil {
		return nil, nil
	}
	var bb [native.FieldBytes]byte
	copy(bb[:], k)
	s, err := bls12381.Bls12381FqNew().SetBytes(&bb)
	if err != nil {
		return nil, nil
	}
	return p.Mul(p, s).BigInt()
}

func (curve *Bls12381G1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	p := new(bls12381.G1).Generator()
	var bb [native.FieldBytes]byte
	copy(bb[:], internal.ReverseScalarBytes(k))
	s, err := bls12381.Bls12381FqNew().SetBytes(&bb)
	if err != nil {
		return nil, nil
	}
	return p.Mul(p, s).BigInt()
}

// Hash an arbitrary byte sequence to a G1 point according to the hash-to-curve standard
func (curve *Bls12381G1Curve) Hash(msg []byte) (*big.Int, *big.Int) {
	return new(bls12381.G1).Hash(native.EllipticPointHasherSha256(), msg, []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_")).BigInt()
}

// CompressedBytesFromBigInts takes x and y coordinates and converts them to the BLS compressed point form
func (curve *Bls12381G1Curve) CompressedBytesFromBigInts(x, y *big.Int) ([]byte, error) {
	p, err := new(bls12381.G1).SetBigInt(x, y)
	if err != nil {
		return nil, err
	}
	out := p.ToCompressed()
	return out[:], nil
}
