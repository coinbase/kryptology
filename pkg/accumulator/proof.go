//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// This file implements the zero knowledge proof of knowledge protocol
// described in section 7 of https://eprint.iacr.org/2020/777.pdf
// Note: the paper only describes for non-membership witness case, but we don't
// use non-membership witness. We only implement the membership witness case.

type proofParamsMarshal struct {
	X     []byte `bare:"x"`
	Y     []byte `bare:"y"`
	Z     []byte `bare:"z"`
	Curve string `bare:"curve"`
}

// ProofParams contains four distinct public generators of G1 - X, Y, Z
type ProofParams struct {
	x, y, z curves.Point
}

// New samples X, Y, Z, K
func (p *ProofParams) New(curve *curves.PairingCurve, pk *PublicKey, entropy []byte) (*ProofParams, error) {
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	prefix := bytes.Repeat([]byte{0xFF}, 32)
	data := append(prefix, entropy...)
	data = append(data, pkBytes...)
	p.z = curve.Scalar.Point().Hash(data)

	data[0] = 0xFE
	p.y = curve.Scalar.Point().Hash(data)

	data[0] = 0xFD
	p.x = curve.Scalar.Point().Hash(data)

	return p, nil
}

// MarshalBinary converts ProofParams to bytes
func (p *ProofParams) MarshalBinary() ([]byte, error) {
	if p.x == nil || p.y == nil || p.z == nil {
		return nil, fmt.Errorf("some value x, y, or z is nil")
	}
	tv := &proofParamsMarshal{
		X:     p.x.ToAffineCompressed(),
		Y:     p.y.ToAffineCompressed(),
		Z:     p.z.ToAffineCompressed(),
		Curve: p.x.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary converts bytes to ProofParams
func (p *ProofParams) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("expected non-zero byte sequence")
	}
	tv := new(proofParamsMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}
	x, err := curve.NewIdentityPoint().FromAffineCompressed(tv.X)
	if err != nil {
		return err
	}
	y, err := curve.NewIdentityPoint().FromAffineCompressed(tv.Y)
	if err != nil {
		return err
	}
	z, err := curve.NewIdentityPoint().FromAffineCompressed(tv.Z)
	if err != nil {
		return err
	}
	p.x = x
	p.y = y
	p.z = z
	return nil
}

// MembershipProofCommitting contains value computed in Proof of knowledge and
// Blinding phases as described in section 7 of https://eprint.iacr.org/2020/777.pdf
type MembershipProofCommitting struct {
	eC             curves.Point
	tSigma         curves.Point
	tRho           curves.Point
	deltaSigma     curves.Scalar
	deltaRho       curves.Scalar
	blindingFactor curves.Scalar
	rSigma         curves.Scalar
	rRho           curves.Scalar
	rDeltaSigma    curves.Scalar
	rDeltaRho      curves.Scalar
	sigma          curves.Scalar
	rho            curves.Scalar
	capRSigma      curves.Point
	capRRho        curves.Point
	capRDeltaSigma curves.Point
	capRDeltaRho   curves.Point
	capRE          curves.Scalar
	accumulator    curves.Point
	witnessValue   curves.Scalar
	xG1            curves.Point
	yG1            curves.Point
	zG1            curves.Point
}

// New initiates values of MembershipProofCommitting
func (mpc *MembershipProofCommitting) New(
	witness *MembershipWitness,
	acc *Accumulator,
	pp *ProofParams,
	pk *PublicKey,
) (*MembershipProofCommitting, error) {
	// Randomly select σ, ρ
	sigma := witness.y.Random(crand.Reader)
	rho := witness.y.Random(crand.Reader)

	// E_C = C + (σ + ρ)Z
	t := sigma
	t = t.Add(rho)
	eC := pp.z
	eC = eC.Mul(t)
	eC = eC.Add(witness.c)

	// T_σ = σX
	tSigma := pp.x
	tSigma = tSigma.Mul(sigma)

	// T_ρ = ρY
	tRho := pp.y
	tRho = tRho.Mul(rho)

	// δ_σ = yσ
	deltaSigma := witness.y
	deltaSigma = deltaSigma.Mul(sigma)

	// δ_ρ = yρ
	deltaRho := witness.y
	deltaRho = deltaRho.Mul(rho)

	// Randomly pick r_σ,r_ρ,r_δσ,r_δρ
	rY := witness.y.Random(crand.Reader)
	rSigma := witness.y.Random(crand.Reader)
	rRho := witness.y.Random(crand.Reader)
	rDeltaSigma := witness.y.Random(crand.Reader)
	rDeltaRho := witness.y.Random(crand.Reader)

	// R_σ = r_σ X
	capRSigma := pp.x
	capRSigma = capRSigma.Mul(rSigma)

	// R_ρ = ρY
	capRRho := pp.y
	capRRho = capRRho.Mul(rRho)

	// R_δσ = r_y T_σ - r_δσ X
	negX := pp.x
	negX = negX.Neg()
	capRDeltaSigma := tSigma.Mul(rY)
	capRDeltaSigma = capRDeltaSigma.Add(negX.Mul(rDeltaSigma))

	// R_δρ = r_y T_ρ - r_δρ Y
	negY := pp.y
	negY = negY.Neg()
	capRDeltaRho := tRho.Mul(rY)
	capRDeltaRho = capRDeltaRho.Add(negY.Mul(rDeltaRho))

	// P~
	g2 := pk.value.Generator()

	// -r_δσ - r_δρ
	exp := rDeltaSigma
	exp = exp.Add(rDeltaRho)
	exp = exp.Neg()

	// -r_σ - r_ρ
	exp2 := rSigma
	exp2 = exp2.Add(rRho)
	exp2 = exp2.Neg()

	// rY * eC
	rYeC := eC.Mul(rY)

	// (-r_δσ - r_δρ)*Z
	expZ := pp.z.Mul(exp)

	// (-r_σ - r_ρ)*Z
	exp2Z := pp.z.Mul(exp2)

	// Prepare
	rYeCPrep := rYeC.(curves.PairingPoint)
	g2Prep := g2.(curves.PairingPoint)
	expZPrep := expZ.(curves.PairingPoint)
	exp2ZPrep := exp2Z.(curves.PairingPoint)
	pkPrep := pk.value

	// Pairing
	capRE := g2Prep.MultiPairing(rYeCPrep, g2Prep, expZPrep, g2Prep, exp2ZPrep, pkPrep)

	return &MembershipProofCommitting{
		eC,
		tSigma,
		tRho,
		deltaSigma,
		deltaRho,
		rY,
		rSigma,
		rRho,
		rDeltaSigma,
		rDeltaRho,
		sigma,
		rho,
		capRSigma,
		capRRho,
		capRDeltaSigma,
		capRDeltaRho,
		capRE,
		acc.value,
		witness.y,
		pp.x,
		pp.y,
		pp.z,
	}, nil
}

// GetChallenge returns bytes that need to be hashed for generating challenge.
// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
func (mpc MembershipProofCommitting) GetChallengeBytes() []byte {
	res := mpc.accumulator.ToAffineCompressed()
	res = append(res, mpc.eC.ToAffineCompressed()...)
	res = append(res, mpc.tSigma.ToAffineCompressed()...)
	res = append(res, mpc.tRho.ToAffineCompressed()...)
	res = append(res, mpc.capRE.Bytes()...)
	res = append(res, mpc.capRSigma.ToAffineCompressed()...)
	res = append(res, mpc.capRRho.ToAffineCompressed()...)
	res = append(res, mpc.capRDeltaSigma.ToAffineCompressed()...)
	res = append(res, mpc.capRDeltaRho.ToAffineCompressed()...)
	return res
}

// GenProof computes the s values for Fiat-Shamir and return the actual
// proof to be sent to the verifier given the challenge c.
func (mpc *MembershipProofCommitting) GenProof(c curves.Scalar) *MembershipProof {
	// s_y = r_y + c*y
	sY := schnorr(mpc.blindingFactor, mpc.witnessValue, c)
	// s_σ = r_σ + c*σ
	sSigma := schnorr(mpc.rSigma, mpc.sigma, c)
	// s_ρ = r_ρ + c*ρ
	sRho := schnorr(mpc.rRho, mpc.rho, c)
	// s_δσ = rδσ + c*δ_σ
	sDeltaSigma := schnorr(mpc.rDeltaSigma, mpc.deltaSigma, c)
	// s_δρ = rδρ + c*δ_ρ
	sDeltaRho := schnorr(mpc.rDeltaRho, mpc.deltaRho, c)

	return &MembershipProof{
		mpc.eC,
		mpc.tSigma,
		mpc.tRho,
		sSigma,
		sRho,
		sDeltaSigma,
		sDeltaRho,
		sY,
	}
}

func schnorr(r, v, challenge curves.Scalar) curves.Scalar {
	res := v
	res = res.Mul(challenge)
	res = res.Add(r)
	return res
}

type membershipProofMarshal struct {
	EC          []byte `bare:"e_c"`
	TSigma      []byte `bare:"t_sigma"`
	TRho        []byte `bare:"t_rho"`
	SSigma      []byte `bare:"s_sigma"`
	SRho        []byte `bare:"s_rho"`
	SDeltaSigma []byte `bare:"s_delta_sigma"`
	SDeltaRho   []byte `bare:"s_delta_rho"`
	SY          []byte `bare:"s_y"`
	Curve       string `bare:"curve"`
}

// MembershipProof contains values in the proof to be verified
type MembershipProof struct {
	eC          curves.Point
	tSigma      curves.Point
	tRho        curves.Point
	sSigma      curves.Scalar
	sRho        curves.Scalar
	sDeltaSigma curves.Scalar
	sDeltaRho   curves.Scalar
	sY          curves.Scalar
}

// Finalize computes values in the proof to be verified.
func (mp *MembershipProof) Finalize(acc *Accumulator, pp *ProofParams, pk *PublicKey, challenge curves.Scalar) *MembershipProofFinal {
	// R_σ = s_δ X + c T_σ
	negTSigma := mp.tSigma
	negTSigma = negTSigma.Neg()
	capRSigma := pp.x.Mul(mp.sSigma)
	capRSigma = capRSigma.Add(negTSigma.Mul(challenge))

	// R_ρ = s_ρ Y + c T_ρ
	negTRho := mp.tRho
	negTRho = negTRho.Neg()
	capRRho := pp.y.Mul(mp.sRho)
	capRRho = capRRho.Add(negTRho.Mul(challenge))

	// R_δσ =  s_y T_σ - s_δσ X
	negX := pp.x
	negX = negX.Neg()
	capRDeltaSigma := mp.tSigma.Mul(mp.sY)
	capRDeltaSigma = capRDeltaSigma.Add(negX.Mul(mp.sDeltaSigma))

	// R_δρ =  s_y T_ρ - s_δρ Y
	negY := pp.y
	negY = negY.Neg()
	capRDeltaRho := mp.tRho.Mul(mp.sY)
	capRDeltaRho = capRDeltaRho.Add(negY.Mul(mp.sDeltaRho))

	// tildeP
	g2 := pk.value.Generator()

	// Compute capRE, the pairing
	// E_c * s_y
	eCsY := mp.eC.Mul(mp.sY)

	// (-s_delta_sigma - s_delta_rho) * Z
	exp := mp.sDeltaSigma
	exp = exp.Add(mp.sDeltaRho)
	exp = exp.Neg()
	expZ := pp.z.Mul(exp)

	// (-c) * V
	exp = challenge.Neg()
	expV := acc.value.Mul(exp)

	// E_c * s_y + (-s_delta_sigma - s_delta_rho) * Z + (-c) * V
	lhs := eCsY.Add(expZ).Add(expV)

	// (-s_sigma - s_rho) * Z
	exp = mp.sSigma
	exp = exp.Add(mp.sRho)
	exp = exp.Neg()
	expZ2 := pp.z.Mul(exp)

	// E_c * c
	cEc := mp.eC.Mul(challenge)

	// (-s_sigma - s_rho) * Z + E_c * c
	rhs := cEc.Add(expZ2)

	// Prepare
	lhsPrep := lhs.(curves.PairingPoint)
	g2Prep := g2.(curves.PairingPoint)
	rhsPrep := rhs.(curves.PairingPoint)
	pkPrep := pk.value

	// capRE
	capRE := g2Prep.MultiPairing(lhsPrep, g2Prep, rhsPrep, pkPrep)

	return &MembershipProofFinal{
		acc.value,
		mp.eC,
		mp.tSigma,
		mp.tRho,
		capRE,
		capRSigma,
		capRRho,
		capRDeltaSigma,
		capRDeltaRho,
	}
}

// MarshalBinary converts MembershipProof to bytes
func (mp MembershipProof) MarshalBinary() ([]byte, error) {
	tv := &membershipProofMarshal{
		EC:          mp.eC.ToAffineCompressed(),
		TSigma:      mp.tSigma.ToAffineCompressed(),
		TRho:        mp.tRho.ToAffineCompressed(),
		SSigma:      mp.sSigma.Bytes(),
		SRho:        mp.sRho.Bytes(),
		SDeltaSigma: mp.sDeltaSigma.Bytes(),
		SDeltaRho:   mp.sDeltaRho.Bytes(),
		SY:          mp.sY.Bytes(),
		Curve:       mp.eC.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary converts bytes to MembershipProof
func (mp *MembershipProof) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("expected non-zero byte sequence")
	}
	tv := new(membershipProofMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}
	eC, err := curve.NewIdentityPoint().FromAffineCompressed(tv.EC)
	if err != nil {
		return err
	}
	tSigma, err := curve.NewIdentityPoint().FromAffineCompressed(tv.TSigma)
	if err != nil {
		return err
	}
	tRho, err := curve.NewIdentityPoint().FromAffineCompressed(tv.TRho)
	if err != nil {
		return err
	}
	sSigma, err := curve.NewScalar().SetBytes(tv.SSigma)
	if err != nil {
		return err
	}
	sRho, err := curve.NewScalar().SetBytes(tv.SRho)
	if err != nil {
		return err
	}
	sDeltaSigma, err := curve.NewScalar().SetBytes(tv.SDeltaSigma)
	if err != nil {
		return err
	}
	sDeltaRho, err := curve.NewScalar().SetBytes(tv.SDeltaRho)
	if err != nil {
		return err
	}
	sY, err := curve.NewScalar().SetBytes(tv.SY)
	if err != nil {
		return err
	}

	mp.eC = eC
	mp.tSigma = tSigma
	mp.tRho = tRho
	mp.sSigma = sSigma
	mp.sRho = sRho
	mp.sDeltaSigma = sDeltaSigma
	mp.sDeltaRho = sDeltaRho
	mp.sY = sY

	return nil
}

// MembershipProofFinal contains values that are input to Fiat-Shamir Heuristic
type MembershipProofFinal struct {
	accumulator    curves.Point
	eC             curves.Point
	tSigma         curves.Point
	tRho           curves.Point
	capRE          curves.Scalar
	capRSigma      curves.Point
	capRRho        curves.Point
	capRDeltaSigma curves.Point
	capRDeltaRho   curves.Point
}

// GetChallenge computes Fiat-Shamir Heuristic taking input values of MembershipProofFinal
func (m MembershipProofFinal) GetChallenge(curve *curves.PairingCurve) curves.Scalar {
	res := m.accumulator.ToAffineCompressed()
	res = append(res, m.eC.ToAffineCompressed()...)
	res = append(res, m.tSigma.ToAffineCompressed()...)
	res = append(res, m.tRho.ToAffineCompressed()...)
	res = append(res, m.capRE.Bytes()...)
	res = append(res, m.capRSigma.ToAffineCompressed()...)
	res = append(res, m.capRRho.ToAffineCompressed()...)
	res = append(res, m.capRDeltaSigma.ToAffineCompressed()...)
	res = append(res, m.capRDeltaRho.ToAffineCompressed()...)
	challenge := curve.Scalar.Hash(res)
	return challenge
}
