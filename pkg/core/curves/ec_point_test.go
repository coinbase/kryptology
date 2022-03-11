//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	tt "github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
)

func TestIsIdentity(t *testing.T) {
	// Should be Point at infinity
	identity := &EcPoint{btcec.S256(), core.Zero, core.Zero}
	require.True(t, identity.IsIdentity())
}

func TestNewScalarBaseMultZero(t *testing.T) {
	// Should be Point at infinity
	curve := btcec.S256()
	num := big.NewInt(0)
	p, err := NewScalarBaseMult(curve, num)
	if err != nil {
		t.Errorf("NewScalarBaseMult failed: %v", err)
	}
	if p == nil {
		t.Errorf("NewScalarBaseMult failed when it should've succeeded.")
	}
}

func TestNewScalarBaseMultOne(t *testing.T) {
	// Should be base Point
	curve := btcec.S256()
	num := big.NewInt(1)
	p, err := NewScalarBaseMult(curve, num)
	if err != nil {
		t.Errorf("NewScalarBaseMult failed: %v", err)
	}
	if p == nil {
		t.Errorf("NewScalarBaseMult failed when it should've succeeded.")
		t.FailNow()
	}
	if !bytes.Equal(p.Bytes(), append(curve.Gx.Bytes(), curve.Gy.Bytes()...)) {
		t.Errorf("NewScalarBaseMult should've returned the base Point.")
	}
}

func TestNewScalarBaseMultNeg(t *testing.T) {
	curve := btcec.S256()
	num := big.NewInt(-1)
	p, err := NewScalarBaseMult(curve, num)
	if err != nil {
		t.Errorf("NewScalarBaseMult failed: %v", err)
	}
	if p == nil {
		t.Errorf("NewScalarBaseMult failed when it should've succeeded.")
		t.FailNow()
	}
	num.Mod(num, curve.N)

	e, err := NewScalarBaseMult(curve, num)
	if err != nil {
		t.Errorf("NewScalarBaseMult failed: %v", err)
	}
	if e == nil {
		t.Errorf("NewScalarBaseMult failed when it should've succeeded.")
		t.FailNow()
	}

	if !bytes.Equal(p.Bytes(), e.Bytes()) {
		t.Errorf("NewScalarBaseMult should've returned the %v, found: %v", e, p)
	}
}

func TestScalarMultZero(t *testing.T) {
	// Should be Point at infinity
	curve := btcec.S256()
	p := &EcPoint{
		Curve: curve,
		X:     curve.Gx,
		Y:     curve.Gy,
	}
	num := big.NewInt(0)
	q, err := p.ScalarMult(num)
	if err != nil {
		t.Errorf("ScalarMult failed: %v", err)
	}
	if q == nil {
		t.Errorf("ScalarMult failed when it should've succeeded.")
		t.FailNow()
	}
	if !q.IsIdentity() {
		t.Errorf("ScalarMult should've returned the identity Point.")
	}
}

func TestScalarMultOne(t *testing.T) {
	// Should be base Point
	curve := btcec.S256()
	p := &EcPoint{
		Curve: curve,
		X:     curve.Gx,
		Y:     curve.Gy,
	}
	num := big.NewInt(1)
	q, err := p.ScalarMult(num)
	if err != nil {
		t.Errorf("ScalarMult failed: %v", err)
	}
	if q == nil {
		t.Errorf("ScalarMult failed when it should've succeeded.")
		t.FailNow()
	}
	if !bytes.Equal(q.Bytes(), append(curve.Gx.Bytes(), curve.Gy.Bytes()...)) {
		t.Errorf("ScalarMult should've returned the base Point.")
	}
}

func TestScalarMultNeg(t *testing.T) {
	curve := btcec.S256()
	p := &EcPoint{
		Curve: curve,
		X:     curve.Gx,
		Y:     curve.Gy,
	}
	num := big.NewInt(-1)
	q, err := p.ScalarMult(num)
	if err != nil {
		t.Errorf("ScalarMult failed: %v", err)
	}
	if q == nil {
		t.Errorf("ScalarMult failed when it should've succeeded.")
	}
	num.Mod(num, curve.N)

	e, err := p.ScalarMult(num)
	if err != nil {
		t.Errorf("ScalarMult failed: %v", err)
	}
	if e == nil {
		t.Errorf("ScalarMult failed when it should've succeeded.")
		t.FailNow()
	}

	if !bytes.Equal(q.Bytes(), e.Bytes()) {
		t.Errorf("ScalarMult should've returned the %v, found: %v", e, p)
	}
}

func TestEcPointAddSimple(t *testing.T) {
	curve := btcec.S256()
	num := big.NewInt(1)
	p1, _ := NewScalarBaseMult(curve, num)

	p2, _ := NewScalarBaseMult(curve, num)
	p3, err := p1.Add(p2)
	if err != nil {
		t.Errorf("EcPoint.Add failed: %v", err)
	}
	num = big.NewInt(2)

	ep, _ := NewScalarBaseMult(curve, num)

	if !bytes.Equal(ep.Bytes(), p3.Bytes()) {
		t.Errorf("EcPoint.Add failed: should equal %v, found: %v", ep, p3)
	}
}

func TestEcPointAddCommunicative(t *testing.T) {
	curve := btcec.S256()
	a, _ := core.Rand(curve.Params().N)
	b, _ := core.Rand(curve.Params().N)

	p1, _ := NewScalarBaseMult(curve, a)
	p2, _ := NewScalarBaseMult(curve, b)
	p3, err := p1.Add(p2)
	if err != nil {
		t.Errorf("EcPoint.Add failed: %v", err)
	}
	p4, err := p2.Add(p1)
	if err != nil {
		t.Errorf("EcPoint.Add failed: %v", err)
	}
	if !bytes.Equal(p3.Bytes(), p4.Bytes()) {
		t.Errorf("EcPoint.Add Communicative not valid")
	}
}

func TestEcPointAddNeg(t *testing.T) {
	curve := btcec.S256()
	num := big.NewInt(-1)

	p1, _ := NewScalarBaseMult(curve, num)
	num.Abs(num)

	p2, _ := NewScalarBaseMult(curve, num)

	p3, err := p1.Add(p2)

	if err != nil {
		t.Errorf("EcPoint.Add failed: %v", err)
	}
	zero := make([]byte, 64)
	if !bytes.Equal(zero, p3.Bytes()) {
		t.Errorf("Expected value to be zero, found: %v", p3)
	}
}

func TestEcPointBytes(t *testing.T) {
	curve := btcec.S256()

	point, err := NewScalarBaseMult(curve, big.NewInt(2))
	require.NoError(t, err)
	data := point.Bytes()
	point2, err := PointFromBytesUncompressed(curve, data)
	require.NoError(t, err)
	if point.X.Cmp(point2.X) != 0 && point.Y.Cmp(point2.Y) != 0 {
		t.Errorf("Points are not equal. Expected %v, found %v", point, point2)
	}

	curve2 := elliptic.P224()
	p2, err := NewScalarBaseMult(curve2, big.NewInt(2))
	require.NoError(t, err)
	dta := p2.Bytes()
	point3, err := PointFromBytesUncompressed(curve2, dta)
	require.NoError(t, err)
	if p2.X.Cmp(point3.X) != 0 && p2.Y.Cmp(point3.Y) != 0 {
		t.Errorf("Points are not equal. Expected %v, found %v", p2, point3)
	}

	curve3 := elliptic.P521()
	p3, err := NewScalarBaseMult(curve3, big.NewInt(2))
	require.NoError(t, err)
	data = p3.Bytes()
	point4, err := PointFromBytesUncompressed(curve3, data)
	require.NoError(t, err)
	if p3.X.Cmp(point4.X) != 0 && p3.Y.Cmp(point4.Y) != 0 {
		t.Errorf("Points are not equal. Expected %v, found %v", p3, point4)
	}
}

func TestEcPointBytesDifferentCurves(t *testing.T) {
	k256 := btcec.S256()
	p224 := elliptic.P224()
	p256 := elliptic.P256()

	kp, err := NewScalarBaseMult(k256, big.NewInt(1))
	require.NoError(t, err)
	data := kp.Bytes()
	_, err = PointFromBytesUncompressed(p224, data)
	require.Error(t, err)
	_, err = PointFromBytesUncompressed(p256, data)
	require.Error(t, err)
}

func TestEcPointBytesInvalidNumberBytes(t *testing.T) {
	curve := btcec.S256()

	for i := 1; i < 64; i++ {
		data := make([]byte, i)
		_, err := PointFromBytesUncompressed(curve, data)
		require.Error(t, err)
	}
	for i := 65; i < 128; i++ {
		data := make([]byte, i)
		_, err := PointFromBytesUncompressed(curve, data)
		require.Error(t, err)
	}
}

func TestEcPointMultRandom(t *testing.T) {
	curve := btcec.S256()
	r, err := core.Rand(curve.N)
	require.NoError(t, err)
	pt, err := NewScalarBaseMult(curve, r)
	require.NoError(t, err)
	require.NotNil(t, pt)
	data := pt.Bytes()
	pt2, err := PointFromBytesUncompressed(curve, data)
	require.NoError(t, err)
	if pt.X.Cmp(pt2.X) != 0 || pt.Y.Cmp(pt2.Y) != 0 {
		t.Errorf("Points are not equal. Expected: %v, found: %v", pt, pt2)
	}
}

func TestIsBasePoint(t *testing.T) {
	k256 := btcec.S256()
	p224 := elliptic.P224()
	p256 := elliptic.P256()

	notG_p224, err := NewScalarBaseMult(p224, tt.B10("9876453120"))
	require.NoError(t, err)

	tests := []struct {
		name     string
		curve    elliptic.Curve
		x, y     *big.Int
		expected bool
	}{
		{"k256-positive", k256, k256.Gx, k256.Gy, true},
		{"p224-positive", p224, p224.Params().Gx, p224.Params().Gy, true},
		{"p256-positive", p256, p256.Params().Gx, p256.Params().Gy, true},

		{"p224-negative", p224, notG_p224.X, notG_p224.Y, false},
		{"p256-negative-wrong-curve", p256, notG_p224.X, notG_p224.Y, false},
		{"k256-negative-doubleGx", k256, k256.Gx, k256.Gx, false},
		{"k256-negative-doubleGy", k256, k256.Gy, k256.Gy, false},
		{"k256-negative-xy-swap", k256, k256.Gy, k256.Gx, false},
		{"k256-negative-oh-oh", k256, core.Zero, core.Zero, false},
	}
	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := EcPoint{test.curve, test.x, test.y}.IsBasePoint()
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestEquals(t *testing.T) {
	k256 := btcec.S256()
	p224 := elliptic.P224()
	p256 := elliptic.P256()
	P_p224, _ := NewScalarBaseMult(p224, tt.B10("9876453120"))
	P1_p224, _ := NewScalarBaseMult(p224, tt.B10("9876453120"))

	P_k256 := &EcPoint{k256, P_p224.X, P_p224.Y}

	id_p224 := &EcPoint{p224, core.Zero, core.Zero}
	id_k256 := &EcPoint{k256, core.Zero, core.Zero}
	id_p256 := &EcPoint{p256, core.Zero, core.Zero}

	tests := []struct {
		name     string
		x, y     *EcPoint
		expected bool
	}{
		{"p224 same pointer", P_p224, P_p224, true},
		{"p224 same Point", P_p224, P1_p224, true},
		{"p224 identity", id_p224, id_p224, true},
		{"p256 identity", id_p256, id_p256, true},
		{"k256 identity", id_k256, id_k256, true},

		{"negative-same x different y", P_p224, &EcPoint{p224, P_p224.X, core.One}, false},
		{"negative-same y different x", P_p224, &EcPoint{p224, core.Two, P_k256.Y}, false},

		{"negative-wrong curve", P_p224, P_k256, false},
		{"negative-wrong curve reversed", P_k256, P_p224, false},
		{"Point is not the identity", P_p224, id_p224, false},
		{"negative nil", P1_p224, nil, false},
		{"identities on wrong curve", id_p256, id_k256, false},
	}
	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.x.Equals(test.y)
			require.Equal(t, test.expected, actual)
		})
	}
}
