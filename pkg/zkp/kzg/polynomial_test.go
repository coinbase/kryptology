package kzg

import (
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
	bls "github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/stretchr/testify/require"
)

func TestNewPolyEval(t *testing.T) {
	poly := new(Polynomial).SetUInt64([]uint64{5, 1})
	x := bls.Bls12381FqNew().SetBigInt(big.NewInt(1))

	require.Equal(t, poly.Evaluate(x).BigInt(), big.NewInt(6))
}

func TestNewPolyLead(t *testing.T) {
	p := new(Polynomial).SetUInt64([]uint64{5, 1})
	lead := p.Coefficients[len(p.Coefficients)-1]
	require.Equal(t, p.Lead(), lead)
}

func TestPolyAddSub(t *testing.T) {
	poly1 := new(Polynomial).SetUInt64([]uint64{1, 0, 5})
	poly2 := new(Polynomial).SetUInt64([]uint64{3, 0, 1})
	poly3 := new(Polynomial).SetUInt64([]uint64{4, 0, 6})

	require.True(t, poly1.Add(poly2).Equal(poly3))
	require.True(t, poly1.Add(poly2).Equal(poly2.Add(poly1)))
}

func TestMulDiv(t *testing.T) {
	a := big.NewInt(1)
	b := big.NewInt(2)
	c := big.NewInt(3)

	d := big.NewInt(4)
	e := big.NewInt(10)
	f := big.NewInt(12)
	g := big.NewInt(9)

	poly1 := new(Polynomial).SetBigInt([]*big.Int{a, b, c})
	poly1sq := new(Polynomial).SetBigInt([]*big.Int{a, d, e, f, g})

	res := poly1.Mul(poly1)
	require.True(t, res.Equal(poly1sq))

	quotient, remainder := res.Div(poly1)
	require.True(t, quotient.Equal(poly1))
	require.True(t, remainder.Equal(new(Polynomial).Zero()))

	poly2 := new(Polynomial).SetBigInt([]*big.Int{c})

	quotient2, remainder2 := res.Add(poly2).Div(poly1)
	require.True(t, quotient2.Equal(poly1))
	require.True(t, remainder2.Equal(poly2))

	quotient3, remainder3 := new(Polynomial).Zero().Div(poly1)
	require.True(t, quotient3.Equal(new(Polynomial).Zero()))
	require.True(t, remainder3.Equal(new(Polynomial).Zero()))

	poly3 := new(Polynomial).SetBigInt([]*big.Int{d, a, f, e, g})

	// Test commutativity
	require.True(t, (poly1.Mul(poly2)).Equal(poly2.Mul(poly1)))
	require.True(t, (poly1.Mul(poly2.Mul(poly3))).Equal(poly3.Mul(poly1.Mul(poly2))))

	// (p1 * (p2/p3)) = ((p1*p2) / p3)
	qtmp, r1 := poly2.Div(poly3)
	q1 := poly1.Mul(qtmp)
	q2, r2 := poly1.Mul(poly2).Div(poly3)
	require.True(t, q1.Equal(q2))
	require.True(t, r1.Mul(poly1).Equal(r2))

	// Test associativity
	require.True(t, (poly1.Mul(poly2.Add(poly3))).Equal(poly1.Mul(poly2).Add(poly1.Mul(poly3))))
}

func TestScalarMulDiv(t *testing.T) {
	a := big.NewInt(1)
	b := big.NewInt(2)
	c := big.NewInt(3)

	d := bls.Bls12381FqNew().SetBigInt(big.NewInt(37))
	e := bls.Bls12381FqNew().SetBigInt(big.NewInt(103))

	poly1 := new(Polynomial).SetBigInt([]*big.Int{c, b, a})

	n := bls.Bls12381FqNew().SetBigInt(c)

	res1 := poly1.ScalarMul(n).ScalarDiv(n)
	require.Equal(t, res1.Equal(poly1), true)
	res2 := poly1.ScalarMul(d).ScalarMul(e).ScalarDiv(bls.Bls12381FqNew().Mul(d, e))
	require.Equal(t, res2.Equal(poly1), true)
}

func TestLagrangeErr(t *testing.T) {
	x0 := bls.Bls12381FqNew().SetUint64(1)
	x1 := bls.Bls12381FqNew().SetUint64(2)
	y0 := bls.Bls12381FqNew().SetUint64(3)

	x := []*native.Field{x0, x1}
	y := []*native.Field{y0}

	_, err := CreateLagrangePolynomial(x, y)
	require.Error(t, err)
}

func TestCreateLagrangePolynomialLinear(t *testing.T) {
	x0 := bls.Bls12381FqNew().SetUint64(1)
	y0 := bls.Bls12381FqNew().SetUint64(2)
	x1 := bls.Bls12381FqNew().SetUint64(3)
	y1 := bls.Bls12381FqNew().SetUint64(4)
	x2 := bls.Bls12381FqNew().SetUint64(5)
	y2 := bls.Bls12381FqNew().SetUint64(6)
	x3 := bls.Bls12381FqNew().SetUint64(7)
	y3 := bls.Bls12381FqNew().SetUint64(8)

	x := []*native.Field{x0, x1, x2, x3}
	y := []*native.Field{y0, y1, y2, y3}

	p, err := CreateLagrangePolynomial(x, y)
	require.NoError(t, err, "Unable to create lagrange polynomial")
	require.True(t, p.Equal(new(Polynomial).SetUInt64([]uint64{1, 1})))

	for i := 0; i < len(x); i++ {
		require.Equal(t, p.Evaluate(x[i]), y[i])
	}
}

func TestZeroPolynomialDividesLagrangePolynomial(t *testing.T) {
	x0 := bls.Bls12381FqNew().SetUint64(0)
	x1 := bls.Bls12381FqNew().SetUint64(4)
	x2 := bls.Bls12381FqNew().SetUint64(11)
	x3 := bls.Bls12381FqNew().SetUint64(15)

	poly := new(Polynomial).SetUInt64([]uint64{5, 7, 3, 1, 1, 1})

	// eval poly at points
	x := []*native.Field{x0, x1, x2, x3}
	y := []*native.Field{}
	for _, val := range x {
		y = append(y, poly.Evaluate(val))
	}

	lp, err := CreateLagrangePolynomial(x, y)
	require.NoError(t, err, "Unable to create lagrange polynomial")

	_, r := poly.Sub(lp).Div(CreateZeroPolynomial(x))
	require.True(t, r.IsZero())
}

func TestCreateZeroPolynomial(t *testing.T) {
	a := bls.Bls12381FqNew().SetUint64(1)
	b := bls.Bls12381FqNew().SetUint64(2)
	c := bls.Bls12381FqNew().SetUint64(3)

	nums := []*native.Field{a, b, c}
	zp := CreateZeroPolynomial(nums)
	zpc := new(Polynomial).SetBigInt(
		[]*big.Int{
			big.NewInt(-6),
			big.NewInt(11),
			big.NewInt(-6),
			big.NewInt(1),
		},
	)
	require.True(t, zp.Equal(zpc))
}
