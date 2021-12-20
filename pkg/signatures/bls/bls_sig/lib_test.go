//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls_sig

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"math/big"
	"testing"
)

func genSecretKey(t *testing.T) *SecretKey {
	ikm := make([]byte, 32)
	sk, err := new(SecretKey).Generate(ikm)
	if err != nil {
		t.Errorf("Couldn't generate secret key")
	}
	return sk
}

func genRandSecretKey(ikm []byte, t *testing.T) *SecretKey {
	sk, err := new(SecretKey).Generate(ikm)
	if err != nil {
		t.Errorf("Couldn't generate secret key")
	}
	return sk
}

func genPublicKeyVt(sk *SecretKey, t *testing.T) *PublicKeyVt {
	pk, err := sk.GetPublicKeyVt()
	if err != nil {
		t.Errorf("Expected GetPublicKeyVt to pass but failed: %v", err)
	}
	return pk
}

func genPublicKey(sk *SecretKey, t *testing.T) *PublicKey {
	pk, err := sk.GetPublicKey()
	if err != nil {
		t.Errorf("GetPublicKey failed. Couldn't generate public key: %v", err)
	}
	return pk
}

func genSignature(sk *SecretKey, message []byte, t *testing.T) *Signature {
	bls := NewSigPop()

	sig, err := bls.Sign(sk, message)
	if err != nil {
		t.Errorf("createSignature couldn't sign message: %v", err)
	}
	return sig
}

func genSignatureVt(sk *SecretKey, message []byte, t *testing.T) *SignatureVt {
	bls := NewSigPopVt()
	sig, err := bls.Sign(sk, message)
	if err != nil {
		t.Errorf("createSignatureVt couldn't sign message: %v", err)
	}
	return sig
}

func readRand(ikm []byte, t *testing.T) {
	n, err := rand.Read(ikm)
	if err != nil || n < len(ikm) {
		t.Errorf("Not enough data was read or an error occurred")
	}
}

func assertSecretKeyGen(seed, expected []byte, t *testing.T) {
	sk, err := new(SecretKey).Generate(seed)
	if err != nil {
		t.Errorf("Expected Generate to succeed but failed")
	}
	actual := sk.value.Bytes()
	if len(actual) != len(expected) {
		t.Errorf("Length of Generate output is incorrect. Expected 32, found: %v\n", len(actual))
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("SecretKey was not as expected")
	}
}

func marshalStruct(value encoding.BinaryMarshaler, t *testing.T) []byte {
	out, err := value.MarshalBinary()
	if err != nil {
		t.Errorf("MarshalBinary failed: %v", err)
	}
	return out
}

func TestSecretKeyZeroBytes(t *testing.T) {
	seed := []byte{}
	_, err := new(SecretKey).Generate(seed)
	if err == nil {
		t.Errorf("Expected Generate to fail but succeeded")
	}
}

func TestMarshalLeadingZeroes(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"no leading zeroes", []byte{74, 53, 59, 227, 218, 192, 145, 160, 167, 230, 64, 98, 3, 114, 245, 225, 226, 228, 64, 23, 23, 193, 231, 156, 172, 111, 251, 168, 246, 144, 86, 4}},
		{"one leading zero byte", []byte{00, 53, 59, 227, 218, 192, 145, 160, 167, 230, 64, 98, 3, 114, 245, 225, 226, 228, 64, 23, 23, 193, 231, 156, 172, 111, 251, 168, 246, 144, 86, 4}},
		{"two leading zeroes", []byte{00, 00, 59, 227, 218, 192, 145, 160, 167, 230, 64, 98, 3, 114, 245, 225, 226, 228, 64, 23, 23, 193, 231, 156, 172, 111, 251, 168, 246, 144, 86, 4}},
	}
	// Run all the tests!
	for _, test := range tests {
		// Marshal
		var k big.Int
		k.SetBytes(test.in)
		bytes, err := SecretKey{k}.MarshalBinary()
		if err != nil {
			t.Errorf("%v", err)
			continue
		}

		// Test that marshal produces a values of the exected len
		t.Run(test.name, func(t *testing.T) {
			if len(bytes) != SecretKeySize {
				t.Errorf("expected len=%v got len=%v", SecretKeySize, len(bytes))
			}
		})

		// Test that we can also unmarhsal correctly
		t.Run(test.name, func(t *testing.T) {
			var actual SecretKey
			err := actual.UnmarshalBinary(bytes)

			// Test for error
			if err != nil {
				t.Errorf("%v", err)
				return
			}

			// Test for correctness
			if actual.value.Cmp(&k) != 0 {
				t.Errorf("unmarshaled doens't match original value")
			}
		})
	}
}

func TestSecretKey32Bytes(t *testing.T) {
	seed := make([]byte, 32)
	expected := []byte{77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73, 236, 42, 129, 156, 204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219, 98, 53}
	assertSecretKeyGen(seed, expected, t)
}

func TestSecretKey128Bytes(t *testing.T) {
	seed := make([]byte, 128)
	expected := []byte{97, 207, 109, 96, 94, 90, 233, 215, 221, 207, 240, 139, 24, 209, 152, 170, 73, 209, 151, 241, 148, 176, 173, 92, 101, 48, 39, 175, 201, 219, 146, 168}
	assertSecretKeyGen(seed, expected, t)
}

func TestRandomSecretKey(t *testing.T) {
	seed := make([]byte, 48)
	_, _ = rand.Read(seed)
	_, err := new(SecretKey).Generate(seed)
	if err != nil {
		t.Errorf("Expected Generate to succeed but failed")
	}
}

func TestSecretKeyToBytes(t *testing.T) {
	sk := genSecretKey(t)
	skBytes := marshalStruct(sk, t)
	sk1 := new(SecretKey)
	err := sk1.UnmarshalBinary(skBytes)
	if err != nil {
		t.Errorf("Expected UnmarshalBinary to pass but failed: %v", err)
	}
	for i, b := range sk1.value.Bytes() {
		if skBytes[i] != b {
			t.Errorf("Expected secret keys to be equal but are different at offset %d: %v != %v", i, skBytes[i], b)
		}
	}
	sk2 := new(SecretKey)
	err = sk2.UnmarshalBinary(skBytes)
	if err != nil {
		t.Errorf("Expected FromBytes to succeed but failed.")
	}
	if !bytes.Equal(marshalStruct(sk2, t), skBytes) {
		t.Errorf("Expected secret keys to be equal but are different")
	}
}

// Verifies that the thresholdize creates the expected number
// of shares
func TestThresholdizeSecretKeyCountsCorrect(t *testing.T) {
	sk := &SecretKey{value: *big.NewInt(248631463258962596)}
	tests := []struct {
		key           *SecretKey
		t, n          uint
		expectedError bool
	}{
		// bad cases
		{sk, 1, 1, true},     // n == 1
		{sk, 1, 5, true},     // t == 1
		{nil, 3, 5, true},    // sk nil
		{sk, 101, 100, true}, // t> n
		{sk, 0, 10, true},    // t == 0
		{sk, 10, 256, true},  // n > 256

		// good cases
		{sk, 10, 10, false},   // t == n
		{sk, 2, 10, false},    // boundary case for t
		{sk, 9, 10, false},    // boundary case for t
		{sk, 10, 255, false},  // boundary case for n
		{sk, 254, 255, false}, // boundary case for t,n
		{sk, 100, 200, false}, // arbitrary t,n values
		{sk, 10, 20, false},   // arbitrary t,n values
		{sk, 15, 200, false},  // arbitrary t,n values
		{sk, 254, 255, false}, // boundary case
		{sk, 255, 255, false}, // boundary case
	}

	// Run all the tests!
	for _, test := range tests {
		shares, err := thresholdizeSecretKey(test.key, test.t, test.n)

		// Check for errors
		if test.expectedError && err == nil {
			t.Errorf("expected an error but received nil. t=%v, n=%v, sk=%v", test.t, test.n, sk)
		}

		// Check for errors
		if !test.expectedError && err != nil {
			t.Errorf("received unexpected error %v. t=%v, n=%v, sk=%v", err, test.t, test.n, sk)
		}

		// Check the share count == n
		if !test.expectedError && test.n != uint(len(shares)) {
			t.Errorf("expected len(shares) = %v != %v (n)", len(shares), test.n)
		}
	}
}
