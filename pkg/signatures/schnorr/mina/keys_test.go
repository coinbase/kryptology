//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
	"github.com/stretchr/testify/require"
)

func TestNewKeys(t *testing.T) {
	pk, sk, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
	require.False(t, sk.value.IsZero())
	require.False(t, pk.value.IsIdentity())
}

func TestSecretKeySignTransaction(t *testing.T) {
	// See https://github.com/MinaProtocol/c-reference-signer/blob/master/reference_signer.c#L15
	skValue := &fq.Fq{
		0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714,
	}
	sk := &SecretKey{value: skValue}
	/*
	   This illustrates constructing and signing the following transaction.
	   amounts are in nanocodas.
	   {
	     "common": {
	       "fee": "3",
	       "fee_token": "1",
	       "fee_payer_pk": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
	       "nonce": "200",
	       "valid_until": "10000",
	       "memo": "E4Yq8cQXC1m9eCYL8mYtmfqfJ5cVdhZawrPQ6ahoAay1NDYfTi44K"
	     },
	     "body": [
	       "Payment",
	       {
	         "source_pk": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
	         "receiver_pk": "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy",
	         "token_id": "1",
	         "amount": "42"
	       }
	     ]
	   }
	*/
	feePayerPk := new(PublicKey)
	err := feePayerPk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	sourcePk := new(PublicKey)
	err = sourcePk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	receiverPk := new(PublicKey)
	err = receiverPk.ParseAddress("B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy")
	require.NoError(t, err)
	txn := &Transaction{
		Fee:        3,
		FeeToken:   1,
		Nonce:      200,
		ValidUntil: 10000,
		Memo:       "this is a memo",
		FeePayerPk: feePayerPk,
		SourcePk:   sourcePk,
		ReceiverPk: receiverPk,
		TokenId:    1,
		Amount:     42,
		Locked:     false,
		Tag:        [3]bool{false, false, false},
		NetworkId:  MainNet,
	}
	sig, err := sk.SignTransaction(txn)
	require.NoError(t, err)
	pk := sk.GetPublicKey()
	require.NoError(t, pk.VerifyTransaction(sig, txn))
}

func TestSecretKeySignMessage(t *testing.T) {
	// See https://github.com/MinaProtocol/c-reference-signer/blob/master/reference_signer.c#L15
	skValue := &fq.Fq{
		0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714,
	}
	sk := &SecretKey{value: skValue}
	sig, err := sk.SignMessage("A test message.")
	require.NoError(t, err)
	pk := sk.GetPublicKey()
	require.NoError(t, pk.VerifyMessage(sig, "A test message."))
}

func TestSecretKeySignTransactionStaking(t *testing.T) {
	// https://github.com/MinaProtocol/c-reference-signer/blob/master/reference_signer.c#L128
	skValue := &fq.Fq{
		0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714,
	}
	sk := &SecretKey{value: skValue}

	feePayerPk := new(PublicKey)
	err := feePayerPk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	sourcePk := new(PublicKey)
	err = sourcePk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	receiverPk := new(PublicKey)
	err = receiverPk.ParseAddress("B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR")
	require.NoError(t, err)
	txn := &Transaction{
		Fee:        3,
		FeeToken:   1,
		Nonce:      10,
		ValidUntil: 4000,
		Memo:       "more delegates more fun",
		FeePayerPk: feePayerPk,
		SourcePk:   sourcePk,
		ReceiverPk: receiverPk,
		TokenId:    1,
		Amount:     0,
		Locked:     false,
		Tag:        [3]bool{false, false, true},
		NetworkId:  MainNet,
	}
	sig, err := sk.SignTransaction(txn)
	require.NoError(t, err)
	pk := sk.GetPublicKey()
	require.NoError(t, pk.VerifyTransaction(sig, txn))
}
