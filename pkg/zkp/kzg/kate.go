package kzg

import (
	crand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
	bls "github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/pkg/errors"
)

var (
	MAX_BIG = new(big.Int)
)

func init() {
	MAX_BIG.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(MAX_BIG, big.NewInt(1))
}

type KZGSetupParamaters struct {
	TG1 []*bls.G1
	TG2 []*bls.G2
}

// NewKZGSetupParamaters returns the kzg10 setup paramaters
func NewKZGSetupParamaters(tg1 []*bls.G1, tg2 []*bls.G2) (*KZGSetupParamaters, error) {
	if len(tg1) != len(tg2) {
		return nil, errors.New("Number of elements in each group must match")
	}
	return &KZGSetupParamaters{
		TG1: tg1,
		TG2: tg2,
	}, nil
}

// Setup performs an untrusted ceremony and returns the kzg10 setup paramaters
func Setup(t int) ([]*bls.G1, []*bls.G2, error) {
	fmt.Printf("WARNING: This is not a secure trusted setup, do not use in a production environment\n")

	if t < 0 {
		return nil, nil, fmt.Errorf("reference string degree must be positive")
	}

	// α: "hidden" number no one should know
	a, err := crand.Int(crand.Reader, MAX_BIG)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create system paramaters")
	}
	alpha := bls.Bls12381FqNew().SetBigInt(a)

	sg1 := make([]*bls.G1, t)
	sg2 := make([]*bls.G2, t)

	// Evaluate point multiplication of progressive powers of alpha
	// [g, g^(α^1), ..., g^(α^t)]
	for i := 0; i < t; i++ {
		sg1[i] = new(bls.G1).Mul(new(bls.G1).Generator(), alpha.Exp(alpha, bls.Bls12381FqNew().SetUint64(uint64(i))))
		sg2[i] = new(bls.G2).Mul(new(bls.G2).Generator(), alpha.Exp(alpha, bls.Bls12381FqNew().SetUint64(uint64(i))))
	}

	return sg1, sg2, nil
}

// EvalPolyG1 evaluates a polynomial in g1 using the setup paramaters
func EvalPolyG1(rs *KZGSetupParamaters, p *Polynomial) (*bls.G1, error) {

	// Confirm that polynomial is valid
	if p.Order() == -1 {
		return nil, errors.New("Cannot evaluate polynomial, must have at least one coefficients")
	}
	if p.Order()+1 > len(rs.TG1) {
		return nil, errors.New("Cannot evaluate polynomial of higher degree than reference string elements")
	}

	// Evalute polynomial in the exponent of the reference string
	// g ^ ( a_0 + a_1 * α ^ 1 + a_2 * α ^ 2 + ... + a_n * α ^ n)
	result := new(bls.G1).Identity()
	for i, c := range p.Coefficients {
		result = result.Add(result, new(bls.G1).Mul(rs.TG1[i], bls.Bls12381FqNew().Set(c)))
	}
	return result, nil
}

// EvalPolyG2 evaluates a polynomial in g2 using the setup paramaters
func EvalPolyG2(rs *KZGSetupParamaters, p *Polynomial) (*bls.G2, error) {

	// Confirm that polynomial is valid
	if p.Order() == -1 {
		return nil, errors.New("Cannot evaluate polynomial, must have at least one coefficients")
	}
	if p.Order()+1 > len(rs.TG2) {
		return nil, errors.New("Cannot evaluate polynomial of higher degree than reference string elements")
	}

	// Evalute polynomial in the exponent of the reference string
	// g ^ ( a_0 + a_1 * α ^ 1 + a_2 * α ^ 2 + ... + a_n * α ^ n)
	result := new(bls.G2).Identity()
	for i, c := range p.Coefficients {
		result = result.Add(result, new(bls.G2).Mul(rs.TG2[i], bls.Bls12381FqNew().Set(c)))
	}
	return result, nil
}

// Commit converts a polynomial to a point in g1 by evaluation with the setup paramaters
func Commit(rs *KZGSetupParamaters, p *Polynomial) (*bls.G1, error) {
	polyEvalG1, err := EvalPolyG1(rs, p)
	if err != nil {
		return nil, err
	}
	return polyEvalG1, nil
}

// VerifyPoly returns 1 if the commitment matches an evaluated polynomial, 0 otherwise
func VerifyPoly(rs *KZGSetupParamaters, c *bls.G1, p *Polynomial) (int, error) {
	pc, err := Commit(rs, p)
	if err != nil {
		return 0, err
	}
	return pc.Equal(c), nil
}

// CreateWitness creates an evaluation proof of a point on a polynomial as a g1 element
func CreateWitness(rs *KZGSetupParamaters, p *Polynomial, x, phiX *native.Field) (*bls.G1, error) {
	n := p.Sub(new(Polynomial).Set([]*native.Field{phiX})) // p - phi(x)
	d := new(Polynomial).Set(                              // x - z
		[]*native.Field{
			bls.Bls12381FqNew().Neg(x),
			bls.Bls12381FqNew().SetOne(),
		},
	)

	// q = ( p - phi(x) ) / (x - z)
	q, r := n.Div(d)
	if !r.IsZero() {
		return nil,
			fmt.Errorf("remainder must be 0")
	}

	// proof = eval(q)
	e, err := EvalPolyG1(rs, q)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// VerifyEval checks the commitment, proof, input point, and evaluation coincide via pairings
func VerifyEval(rs *KZGSetupParamaters, commitment, proof *bls.G1, x, y *native.Field) int {

	// g ^ ( α -  x )
	gmx := new(bls.G2).Neg(new(bls.G2).Mul(new(bls.G2).Generator(), x))
	gamx := new(bls.G2).Add(rs.TG2[1], gmx)

	// g ^ ( f(α) - f(x) )
	gmfx := new(bls.G1).Neg(new(bls.G1).Mul(new(bls.G1).Generator(), y))
	gfamfx := new(bls.G1).Add(commitment, gmfx)

	// e(proof,g^(α-x)) == e(g^(f(α) - f(x)),g)
	p1 := new(bls.Engine)
	p2 := new(bls.Engine)
	e1 := p1.AddPair(proof, gamx).Result()
	e2 := p2.AddPair(gfamfx, new(bls.G2).Generator()).Result()
	return e1.Equal(e2)
}

// CreateWitness creates an evaluation proof of multiple points on a polynomial as a g1 element
func CreateWitnessBatch(rs *KZGSetupParamaters, p *Polynomial, x, phiX []*native.Field) (*bls.G1, error) {

	// I(x)
	ix, err := CreateLagrangePolynomial(x, phiX)
	if err != nil {
		return nil, err
	}

	// q(x) = ( p(x) - I(x) ) / z(x)
	q, r := p.Sub(ix).Div(CreateZeroPolynomial(x))
	if !r.IsZero() {
		return nil,
			fmt.Errorf("remainder must be 0")
	}

	// proof = eval(q(x))
	e, err := EvalPolyG1(rs, q)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// VerifyEvalBatch checks the commitment, proof, input points, and evaluation coincide via pairings
func VerifyEvalBatch(rs *KZGSetupParamaters, commitment, proof *bls.G1, z, y []*native.Field) (int, error) {

	// I(x)
	ix, err := CreateLagrangePolynomial(z, y)
	if err != nil {
		return 0, err
	}

	// f(I(x))
	fiG1, err := EvalPolyG1(rs, ix)
	if err != nil {
		return 0, err
	}

	// f(z(x))
	fzG2, err := EvalPolyG2(rs, CreateZeroPolynomial(z))
	if err != nil {
		return 0, err
	}

	// c - f(I(x))
	cmit := new(bls.G1).Add(commitment, new(bls.G1).Neg(fiG1))

	// e(proof, f(z(x))) == e(c - f(I(x)), g)
	p1 := new(bls.Engine)
	p2 := new(bls.Engine)
	e1 := p1.AddPair(proof, fzG2).Result()
	e2 := p2.AddPair(cmit, new(bls.G2).Generator()).Result()
	return e1.Equal(e2), nil
}
