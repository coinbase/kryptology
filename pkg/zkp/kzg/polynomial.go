package kzg

import (
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
	bls "github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/pkg/errors"
)

func higherOrderPoly(a, b *Polynomial) (*Polynomial, *Polynomial) {
	if a.Order() >= b.Order() {
		return a, b
	}
	return b, a
}

func makeScalarArray(size int) []*native.Field {
	arr := make([]*native.Field, size)
	for i := 0; i < len(arr); i++ {
		arr[i] = bls.Bls12381FqNew().SetZero()
	}
	return arr
}

// The zero polynomial is defined as:
// z(x) = (x - z_0) * (x - z_1) * ... * (x - z_{k-1})
func CreateZeroPolynomial(z []*native.Field) *Polynomial {
	zp := new(Polynomial).Set( // x - z
		[]*native.Field{
			bls.Bls12381FqNew().Neg(z[0]),
			bls.Bls12381FqNew().SetOne(),
		},
	)
	for i := 1; i < len(z); i++ {
		zp = zp.Mul(
			new(Polynomial).Set(
				[]*native.Field{
					bls.Bls12381FqNew().Neg(z[i]),
					bls.Bls12381FqNew().SetOne(),
				},
			),
		)
	}
	return zp
}

// CreateLagrangePolynomial uses point data to interpolate
// a polynomial that hits all the points
func CreateLagrangePolynomial(z, y []*native.Field) (*Polynomial, error) {
	if len(z) != len(y) {
		return nil, errors.New("Cannot interpolate mismatched xy points")
	}

	p := new(Polynomial).Zero()
	lb := new(Polynomial).Zero()

	for i := 0; i < len(z); i++ {
		for j := 0; j < len(z); j++ {
			if i == j {
				continue
			}

			// Calculate components of basis polynomial
			n := new(Polynomial).Set( // (x - z_j)
				[]*native.Field{
					bls.Bls12381FqNew().Neg(z[j]),
					bls.Bls12381FqNew().SetOne(),
				},
			)
			d := bls.Bls12381FqNew().Sub(z[i], z[j]) // (z_i - z_j)
			bp := n.ScalarDiv(d)

			if lb.IsZero() {
				lb = bp
			} else {
				lb = lb.Mul(bp)
			}
		}

		p = p.Add(lb.ScalarMul(y[i]))
		lb = new(Polynomial).Zero()
	}

	return p, nil
}

type Polynomial struct {
	Coefficients []*native.Field
}

// Clean removes all higher order terms
// whose coefficient is zero
func (p *Polynomial) Clean() *Polynomial {
	trailingIndex := 0
	for i := p.Order(); i >= 0; i-- {
		if p.Coefficients[i].IsZero() == 0 {
			trailingIndex = i
			break
		}
	}
	p.Coefficients = p.Coefficients[0 : trailingIndex+1]
	return p
}

// Order returns the order of the polynomial
func (p *Polynomial) Order() int {
	return len(p.Coefficients) - 1
}

// Copy returns a new copy of a polynomial
func (p *Polynomial) Copy() *Polynomial {
	copyCoeffs := make([]*native.Field, len(p.Coefficients))
	for i := 0; i < len(p.Coefficients); i++ {
		copyCoeffs[i] = bls.Bls12381FqNew().Set(p.Coefficients[i])
	}
	return new(Polynomial).Set(copyCoeffs)
}

// Equal only returns true if both polynomial coefficients are equal
func (p *Polynomial) Equal(other *Polynomial) bool {
	if p.Order() != other.Order() {
		return false
	}
	for i, v := range p.Coefficients {
		if v.Cmp(other.Coefficients[i]) != 0 {
			return false
		}
	}
	return true
}

// Zero returns zero as a polynomial
func (p *Polynomial) Zero() *Polynomial {
	return new(Polynomial).Set([]*native.Field{bls.Bls12381FqNew().SetZero()})
}

// IsZero returns true if the polynomial zero
func (p *Polynomial) IsZero() bool {
	return p.Equal(new(Polynomial).Zero())
}

// Lead returns the leading coefficient
func (p *Polynomial) Lead() *native.Field {
	return p.Coefficients[len(p.Coefficients)-1]
}

// Set sets the coefficients of the polynomial from field elements
func (p *Polynomial) Set(coefficients []*native.Field) *Polynomial {
	// Let empty array signify zero
	if len(coefficients) == 0 {
		return new(Polynomial).Zero()
	}

	retP := &Polynomial{
		Coefficients: coefficients,
	}
	return retP.Clean()
}

// SetBigInt sets the coefficients of the polynomial from big integers
func (p *Polynomial) SetBigInt(coefficients []*big.Int) *Polynomial {
	// Let empty array signify zero
	if len(coefficients) == 0 {
		return new(Polynomial).Zero()
	}
	p.Coefficients = make([]*native.Field, len(coefficients))
	for i := 0; i < len(coefficients); i++ {
		p.Coefficients[i] = bls.Bls12381FqNew().SetBigInt(coefficients[i])
	}
	return p.Clean()
}

// SetUInt64 sets the coefficients of the polynomial from unsigned integers
func (p *Polynomial) SetUInt64(coefficients []uint64) *Polynomial {
	// Let empty array signify zero
	if len(coefficients) == 0 {
		return new(Polynomial).Zero()
	}
	p.Coefficients = make([]*native.Field, len(coefficients))
	for i := 0; i < len(coefficients); i++ {
		p.Coefficients[i] = bls.Bls12381FqNew().SetUint64(coefficients[i])
	}
	return p.Clean()
}

// Evalute returns the evaluated polynomial at a point x
func (p *Polynomial) Evaluate(x *native.Field) *native.Field {
	result := bls.Bls12381FqNew().Set(p.Coefficients[p.Order()])
	for i := p.Order() - 1; i >= 0; i-- {
		result = bls.Bls12381FqNew().Add(bls.Bls12381FqNew().Mul(result, x), p.Coefficients[i])
	}
	return result
}

// Add adds two polynomials together
func (p *Polynomial) Add(other *Polynomial) *Polynomial {
	a, b := higherOrderPoly(p, other)
	pBig := a.Copy()
	pSmall := b.Copy()

	for i := 0; i < len(pSmall.Coefficients); i++ {
		pBig.Coefficients[i] = bls.Bls12381FqNew().Add(pBig.Coefficients[i], pSmall.Coefficients[i])
	}
	return pBig.Clean()
}

// Sub subtracts polynomials
func (p *Polynomial) Sub(other *Polynomial) *Polynomial {
	a, b := higherOrderPoly(p, other)
	pBig := a.Copy()
	pSmall := b.Copy()

	for i := 0; i < len(pSmall.Coefficients); i++ {
		pBig.Coefficients[i] = bls.Bls12381FqNew().Sub(pBig.Coefficients[i], pSmall.Coefficients[i])
	}
	return pBig.Clean()
}

// Mul multiplies polynomials together
func (p *Polynomial) Mul(other *Polynomial) *Polynomial {
	finalCoeffs := makeScalarArray(p.Order() + other.Order() + 1)
	for i := 0; i < len(p.Coefficients); i++ {
		for j := 0; j < len(other.Coefficients); j++ {
			inter := bls.Bls12381FqNew().Mul(p.Coefficients[i], other.Coefficients[j])
			finalCoeffs[i+j] = bls.Bls12381FqNew().Add(finalCoeffs[i+j], inter)
		}
	}
	return new(Polynomial).Set(finalCoeffs).Clean()
}

// ScalarMul multiplies each coefficient by scalar
func (p *Polynomial) ScalarMul(c *native.Field) *Polynomial {
	pCopy := p.Copy()
	for i := 0; i < len(pCopy.Coefficients); i++ {
		pCopy.Coefficients[i] = bls.Bls12381FqNew().Mul(pCopy.Coefficients[i], c)
	}
	return pCopy
}

// ScalarDiv divides each coefficient by scalar
func (p *Polynomial) ScalarDiv(c *native.Field) *Polynomial {
	pCopy := p.Copy()
	inv, _ := bls.Bls12381FqNew().Invert(c)
	for i := 0; i < len(pCopy.Coefficients); i++ {
		pCopy.Coefficients[i] = bls.Bls12381FqNew().Mul(pCopy.Coefficients[i], inv)
	}
	return pCopy
}

// Div divides two polynomials
// ref: https://en.wikipedia.org/wiki/Polynomial_long_division
func (p *Polynomial) Div(d *Polynomial) (*Polynomial, *Polynomial) {
	if d.IsZero() {
		panic(fmt.Errorf("cannot divide by zero polynomial"))
	}

	q := makeScalarArray(p.Order() + d.Order() + 1)
	r := p

	for !r.IsZero() && (r.Order() >= d.Order()) {

		// q = q + lead(r) / lead(d)
		inv, _ := bls.Bls12381FqNew().Invert(d.Lead())
		t := bls.Bls12381FqNew().Mul(r.Lead(), inv)
		tIndex := len(r.Coefficients) - len(d.Coefficients)
		q[tIndex] = t

		// r = r - (t * d)
		td := new(Polynomial).Set(append(makeScalarArray(tIndex), t)).Mul(d)
		rScalars := r.Sub(td)
		r = new(Polynomial).Set(rScalars.Coefficients).Clean()
	}
	return new(Polynomial).Set(q).Clean(), r.Clean()
}
