//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigAgg(t *testing.T) {
	config := ShareConfiguration{T: 2, N: 3}
	pub, secretShares, _, err := GenerateSharedKey(&config)
	require.NoError(t, err)

	message := []byte("test message")

	// Each party generates a nonce and we combine them together into an aggregate one
	noncePub1, nonceShares1, _, err := GenerateSharedNonce(&config, secretShares[0], pub, message)
	require.NoError(t, err)
	noncePub2, nonceShares2, _, err := GenerateSharedNonce(&config, secretShares[1], pub, message)
	require.NoError(t, err)
	noncePub3, nonceShares3, _, err := GenerateSharedNonce(&config, secretShares[2], pub, message)
	require.NoError(t, err)
	nonceShares := []*NonceShare{
		nonceShares1[0].Add(nonceShares2[0]).Add(nonceShares3[0]),
		nonceShares1[1].Add(nonceShares2[1]).Add(nonceShares3[1]),
		nonceShares1[2].Add(nonceShares2[2]).Add(nonceShares3[2]),
	}

	noncePub := GeAdd(GeAdd(noncePub1, noncePub2), noncePub3)

	sig1 := TSign(message, secretShares[0], pub, nonceShares[0], noncePub)
	sig2 := TSign(message, secretShares[1], pub, nonceShares[1], noncePub)
	sig3 := TSign(message, secretShares[2], pub, nonceShares[2], noncePub)

	// Test signer 1&2 verification
	sig, err := Aggregate([]*PartialSignature{sig1, sig2}, &config)
	require.NoError(t, err)
	assertSignatureVerifies(t, pub, message, sig)

	// Test signer 2&3 verification
	sig, err = Aggregate([]*PartialSignature{sig2, sig3}, &config)
	require.NoError(t, err)
	assertSignatureVerifies(t, pub, message, sig)

	// Test signer 1&3 verification
	sig, err = Aggregate([]*PartialSignature{sig1, sig3}, &config)
	require.NoError(t, err)
	assertSignatureVerifies(t, pub, message, sig)
}

func TestSigAgg_validations(t *testing.T) {
	config := ShareConfiguration{T: 2, N: 3}
	_, err := Aggregate([]*PartialSignature{}, &config)
	require.EqualError(t, err, "ted25519: sigs must be non-empty")

	sig1bytes, _ := hex.DecodeString(
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
			"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	)
	sig2bytes, _ := hex.DecodeString(
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
			"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	)
	sig1 := NewPartialSignature(1, sig1bytes)
	sig2 := NewPartialSignature(2, sig2bytes)

	_, err = Aggregate([]*PartialSignature{sig1, sig2}, &config)
	require.EqualError(
		t,
		err,
		fmt.Sprintf("ted25519: unexpected nonce pubkey. got: %x expected: %x", sig2bytes[:32], sig1bytes[:32]),
	)
}

func assertSignatureVerifies(t *testing.T, pub, message, sig []byte) {
	ok, _ := Verify(pub, message, sig)
	if !ok {
		t.Errorf("valid signature rejected")
	}
	wrongMessage := []byte("wrong message")
	ok, _ = Verify(pub, wrongMessage, sig)
	if ok {
		t.Errorf("signature of different message accepted")
	}
}
