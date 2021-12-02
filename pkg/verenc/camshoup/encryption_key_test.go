//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionKeyEncryptSingleMessage(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptSingleMessage")

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
		cs, err := ek.Encrypt(domain, []*big.Int{msg})
		require.NoError(t, err)
		msgs, err := dk.Decrypt(domain, cs)
		require.NoError(t, err)
		require.Equal(t, msgs[0].Cmp(msg), 0)
	}
}

func TestEncryptionKeyEncryptMultipleMessages(t *testing.T) {
	const NumMsgs = 10

	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptMultipleMessages")

	ek, dk, err := NewKeys(NumMsgs, group)
	require.NoError(t, err)

	msgs := make([]*big.Int, NumMsgs)
	for i := 0; i < NumMsgs; i++ {
		msgs[i] = new(big.Int).SetBytes([]byte(fmt.Sprintf("msgs_%d", i+1)))
	}

	cs, err := ek.Encrypt(domain, msgs)
	require.NoError(t, err)
	dmsgs, err := dk.Decrypt(domain, cs)
	require.NoError(t, err)
	for i, m := range msgs {
		require.Equal(t, m.Cmp(dmsgs[i]), 0)
	}
}

func TestEncryptionKeyEncryptInvalidMessages(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestEncryptionKeyEncryptInvalidMessages")

	ek, dk, err := NewKeys(1, group)
	require.NoError(t, err)
	// Too large of message
	msg := new(big.Int).Add(big.NewInt(1), group.n)
	_, err = ek.Encrypt(domain, []*big.Int{msg})
	require.Error(t, err)

	// nil message
	_, err = ek.Encrypt(domain, []*big.Int{nil})
	require.Error(t, err)

	// no messages
	_, err = ek.Encrypt(domain, []*big.Int{})
	require.Error(t, err)

	// invalid domains
	msg = new(big.Int).SetBytes([]byte("test message"))
	cs, err := ek.Encrypt(domain, []*big.Int{msg})
	require.NoError(t, err)
	_, err = dk.Decrypt([]byte{}, cs)
	require.Error(t, err)
}

func TestEncryptionKeyMarshaling(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)
	ek, _, err := NewKeys(1, group)
	require.NoError(t, err)

	bin, err := ek.MarshalBinary()
	require.NoError(t, err)

	ekClone := new(EncryptionKey)
	err = ekClone.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.Equal(t, 0, ek.y2.Cmp(ekClone.y2))
	require.Equal(t, 0, ek.y3.Cmp(ekClone.y3))
	require.Equal(t, 1, len(ekClone.y1))
	require.Equal(t, 0, ek.y1[0].Cmp(ekClone.y1[0]))
}
