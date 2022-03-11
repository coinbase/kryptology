//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestProofParamsMarshal(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	params, err := new(ProofParams).New(curve, pk, []byte("entropy"))
	require.NoError(t, err)
	require.NotNil(t, params.x)
	require.NotNil(t, params.y)
	require.NotNil(t, params.z)

	bytes, err := params.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	params2 := &ProofParams{
		curve.PointG1.Generator(),
		curve.PointG1.Generator(),
		curve.PointG1.Generator(),
	}
	err = params2.UnmarshalBinary(bytes)
	require.NoError(t, err)
	require.True(t, params.x.Equal(params2.x))
	require.True(t, params.y.Equal(params2.y))
	require.True(t, params.z.Equal(params2.z))
}

func TestMembershipProof(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	element1 := curve.Scalar.Hash([]byte("3"))
	element2 := curve.Scalar.Hash([]byte("4"))
	element3 := curve.Scalar.Hash([]byte("5"))
	element4 := curve.Scalar.Hash([]byte("6"))
	element5 := curve.Scalar.Hash([]byte("7"))
	element6 := curve.Scalar.Hash([]byte("8"))
	element7 := curve.Scalar.Hash([]byte("9"))
	elements := []Element{element1, element2, element3, element4, element5, element6, element7}

	// Initiate a new accumulator
	acc, err := new(Accumulator).WithElements(curve, sk, elements)
	require.NoError(t, err)
	require.NotNil(t, acc.value)

	// Initiate a new membership witness for value elements[3]
	wit, err := new(MembershipWitness).New(elements[3], acc, sk)
	require.NoError(t, err)
	require.Equal(t, wit.y, elements[3])

	// Create proof parameters, which contains randomly sampled G1 points X, Y, Z, K
	params, err := new(ProofParams).New(curve, pk, []byte("entropy"))
	require.NoError(t, err)
	require.NotNil(t, params.x)
	require.NotNil(t, params.y)
	require.NotNil(t, params.z)

	mpc, err := new(MembershipProofCommitting).New(wit, acc, params, pk)
	require.NoError(t, err)
	testMPC(t, mpc)

	challenge := curve.Scalar.Hash(mpc.GetChallengeBytes())
	require.NotNil(t, challenge)

	proof := mpc.GenProof(challenge)
	require.NotNil(t, proof)
	testProof(t, proof)

	finalProof, err := proof.Finalize(acc, params, pk, challenge)
	require.NoError(t, err)
	require.NotNil(t, finalProof)
	testFinalProof(t, finalProof)

	challenge2 := finalProof.GetChallenge(curve)
	require.Equal(t, challenge, challenge2)

	// Check we can still have a valid proof even if accumulator and witness are updated
	data1 := curve.Scalar.Hash([]byte("1"))
	data2 := curve.Scalar.Hash([]byte("2"))
	data3 := curve.Scalar.Hash([]byte("3"))
	data4 := curve.Scalar.Hash([]byte("4"))
	data5 := curve.Scalar.Hash([]byte("5"))
	data := []Element{data1, data2, data3, data4, data5}
	additions := data[0:2]
	deletions := data[2:5]
	_, coefficients, err := acc.Update(sk, additions, deletions)
	require.NoError(t, err)
	require.NotNil(t, coefficients)

	_, err = wit.BatchUpdate(additions, deletions, coefficients)
	require.NoError(t, err)

	newParams, err := new(ProofParams).New(curve, pk, []byte("entropy"))
	require.NoError(t, err)
	require.NotNil(t, newParams.x)
	require.NotNil(t, newParams.y)
	require.NotNil(t, newParams.z)

	newMPC, err := new(MembershipProofCommitting).New(wit, acc, newParams, pk)
	require.NoError(t, err)
	testMPC(t, newMPC)

	challenge3 := curve.Scalar.Hash(newMPC.GetChallengeBytes())
	require.NotNil(t, challenge3)

	newProof := newMPC.GenProof(challenge3)
	require.NotNil(t, newProof)
	testProof(t, newProof)

	newFinalProof, err := newProof.Finalize(acc, newParams, pk, challenge3)
	require.NoError(t, err)
	require.NotNil(t, newFinalProof)
	testFinalProof(t, newFinalProof)

	challenge4 := newFinalProof.GetChallenge(curve)
	require.Equal(t, challenge3, challenge4)
}

func testMPC(t *testing.T, mpc *MembershipProofCommitting) {
	require.NotNil(t, mpc.eC)
	require.NotNil(t, mpc.tSigma)
	require.NotNil(t, mpc.tRho)
	require.NotNil(t, mpc.deltaSigma)
	require.NotNil(t, mpc.deltaRho)
	require.NotNil(t, mpc.blindingFactor)
	require.NotNil(t, mpc.rSigma)
	require.NotNil(t, mpc.rRho)
	require.NotNil(t, mpc.rDeltaSigma)
	require.NotNil(t, mpc.rDeltaRho)
	require.NotNil(t, mpc.sigma)
	require.NotNil(t, mpc.rho)
	require.NotNil(t, mpc.capRSigma)
	require.NotNil(t, mpc.capRRho)
	require.NotNil(t, mpc.capRDeltaSigma)
	require.NotNil(t, mpc.capRDeltaRho)
	require.NotNil(t, mpc.capRE)
	require.NotNil(t, mpc.accumulator)
	require.NotNil(t, mpc.witnessValue)
	require.NotNil(t, mpc.xG1)
	require.NotNil(t, mpc.yG1)
	require.NotNil(t, mpc.zG1)
}

func testProof(t *testing.T, proof *MembershipProof) {
	require.NotNil(t, proof.eC)
	require.NotNil(t, proof.tSigma)
	require.NotNil(t, proof.tRho)
	require.NotNil(t, proof.sSigma)
	require.NotNil(t, proof.sRho)
	require.NotNil(t, proof.sDeltaSigma)
	require.NotNil(t, proof.sDeltaRho)
	require.NotNil(t, proof.sY)
}

func testFinalProof(t *testing.T, finalProof *MembershipProofFinal) {
	require.NotNil(t, finalProof.accumulator)
	require.NotNil(t, finalProof.eC)
	require.NotNil(t, finalProof.tSigma)
	require.NotNil(t, finalProof.tRho)
	require.NotNil(t, finalProof.capRE)
	require.NotNil(t, finalProof.capRSigma)
	require.NotNil(t, finalProof.capRRho)
	require.NotNil(t, finalProof.capRDeltaSigma)
	require.NotNil(t, finalProof.capRDeltaRho)
}
