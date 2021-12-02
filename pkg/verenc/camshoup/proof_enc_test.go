//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionKeyEncryptAndProve(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, dk, err := NewKeys(1, group)
	require.NoError(t, err)

	testMsgs := []*big.Int{
		big.NewInt(0),
		big.NewInt(10),
		big.NewInt(20),
		big.NewInt(30),
		big.NewInt(40),
		big.NewInt(50),
		big.NewInt(100),
		big.NewInt(1000),
		big.NewInt(10000),
		big.NewInt(100000),
		big.NewInt(1000000),
	}
	for _, msg := range testMsgs {
		cs, proof, err := ek.EncryptAndProve(domain, []*big.Int{msg})
		require.NoError(t, err)

		err = ek.VerifyEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		dmsg, err := dk.Decrypt(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.Cmp(dmsg[0]))
	}
}

func TestEncryptionKeyEncryptAndProveBlindings(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptAndProveBlindings")

	ek, dk, err := NewKeys(1, group)
	require.NoError(t, err)

	testMsgs := []*struct {
		test, blinding *big.Int
	}{
		{big.NewInt(0), big.NewInt(1)},
		{big.NewInt(10), big.NewInt(2)},
		{big.NewInt(20), big.NewInt(3)},
		{big.NewInt(30), big.NewInt(4)},
		{big.NewInt(40), big.NewInt(5)},
		{big.NewInt(50), big.NewInt(6)},
		{big.NewInt(100), big.NewInt(7)},
		{big.NewInt(1000), big.NewInt(8)},
		{big.NewInt(10000), big.NewInt(9)},
		{big.NewInt(100000), big.NewInt(10)},
		{big.NewInt(1000000), big.NewInt(11)},
	}
	for _, msg := range testMsgs {
		cs, proof, err := ek.EncryptAndProveBlindings(domain, []*big.Int{msg.test}, []*big.Int{msg.blinding})
		require.NoError(t, err)

		err = ek.VerifyEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		dmsg, err := dk.Decrypt(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.test.Cmp(dmsg[0]))
	}
}

func TestEncryptionKeyEncryptAndProveInvalidInputs(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptAndProveInvalidInputs")

	ek, _, err := NewKeys(1, group)
	require.NoError(t, err)

	_, _, err = ek.EncryptAndProve(domain, nil)
	require.Error(t, err)

	_, _, err = ek.EncryptAndProve(domain, []*big.Int{})
	require.Error(t, err)

	_, _, err = ek.EncryptAndProveBlindings(domain, []*big.Int{big.NewInt(1)}, nil)
	require.Error(t, err)

	_, _, err = ek.EncryptAndProveBlindings(domain, []*big.Int{big.NewInt(2)}, []*big.Int{})
	require.Error(t, err)

	_, _, err = ek.EncryptAndProveBlindings(domain, []*big.Int{big.NewInt(2)}, []*big.Int{big.NewInt(0)})
	require.Error(t, err)
}
