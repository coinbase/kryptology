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

	ed "filippo.io/edwards25519"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

var ed25519Initonce sync.Once
var ed25519 Ed25519Curve

type Ed25519Curve struct {
	*elliptic.CurveParams
}

func ed25519InitAll() {
	// taken from https://datatracker.ietf.org/doc/html/rfc8032
	ed25519.CurveParams = new(elliptic.CurveParams)
	ed25519.P, _ = new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16)
	ed25519.N, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
	ed25519.Gx = new(big.Int)
	ed25519.Gy = new(big.Int).SetBytes(ed.NewGeneratorPoint().Bytes())
	ed25519.BitSize = 255
	ed25519.Name = "ed25519"
}

func Ed25519() *Ed25519Curve {
	ed25519Initonce.Do(ed25519InitAll)
	return &ed25519
}

func (curve *Ed25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve *Ed25519Curve) IsOnCurve(x, y *big.Int) bool {
	// ignore the x value since Ed25519 is canonical 32 bytes of y according to RFC 8032
	// Set bytes returns an error if not a valid point
	_, err := internal.BigInt2Ed25519Point(y)
	return err == nil
}

func (curve *Ed25519Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	var p1, p2 *ed.Point
	var err error
	if y1.Cmp(big.NewInt(0)) == 0 {
		p1 = ed.NewIdentityPoint()
	} else {
		p1, err = internal.BigInt2Ed25519Point(y1)
	}
	if err != nil {
		panic(err)
	}
	if y2.Cmp(big.NewInt(0)) == 0 {
		p2 = ed.NewIdentityPoint()
	} else {
		p2, err = internal.BigInt2Ed25519Point(y2)
	}
	if err != nil {
		panic(err)
	}
	p1.Add(p1, p2)
	return new(big.Int), new(big.Int).SetBytes(p1.Bytes())
}

func (curve *Ed25519Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := internal.BigInt2Ed25519Point(y1)
	if err != nil {
		panic(err)
	}
	p1, _ := internal.BigInt2Ed25519Point(y1)
	p.Add(p, p1)
	return new(big.Int), new(big.Int).SetBytes(p.Bytes())
}

func (curve *Ed25519Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p, err := internal.BigInt2Ed25519Point(By)
	if err != nil {
		panic(err)
	}
	s, err := internal.BigInt2Ed25519Scalar(new(big.Int).SetBytes(k))
	if err != nil {
		var t [64]byte
		copy(t[:], internal.ReverseScalarBytes(k))
		s, err = ed.NewScalar().SetUniformBytes(t[:])
		if err != nil {
			panic(err)
		}
	}
	p.ScalarMult(s, p)
	return new(big.Int), new(big.Int).SetBytes(p.Bytes())
}

func (curve *Ed25519Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	s, err := internal.BigInt2Ed25519Scalar(new(big.Int).SetBytes(k))
	if err != nil {
		var t [64]byte
		copy(t[:], internal.ReverseScalarBytes(k))
		s, err = ed.NewScalar().SetUniformBytes(t[:])
		if err != nil {
			panic(err)
		}
	}
	p := ed.NewIdentityPoint().ScalarBaseMult(s)
	return new(big.Int), new(big.Int).SetBytes(p.Bytes())
}

func (curve *Ed25519Curve) Neg(Bx, By *big.Int) (*big.Int, *big.Int) {
	var p1 *ed.Point
	var err error
	if By.Cmp(big.NewInt(0)) == 0 {
		p1 = ed.NewIdentityPoint()
	} else {
		p1, err = internal.BigInt2Ed25519Point(By)
		if err != nil {
			panic(err)
		}
	}
	p1.Negate(p1)
	return new(big.Int), new(big.Int).SetBytes(p1.Bytes())
}

func (curve *Ed25519Curve) Hash(msg []byte) (*big.Int, *big.Int) {
	data := new(curves.PointEd25519).Hash(msg).ToAffineCompressed()
	pt, err := ed.NewIdentityPoint().SetBytes(data)
	if err != nil {
		panic(err)
	}
	return new(big.Int), new(big.Int).SetBytes(internal.ReverseScalarBytes(pt.Bytes()))
}
