//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls_sig

import (
	"testing"

	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
)

func generateBasicSignatureG2(sk *SecretKey, msg []byte, t *testing.T) *Signature {
	bls := NewSigBasic()
	sig, err := bls.Sign(sk, msg)
	if err != nil {
		t.Errorf("Basic Sign failed")
	}
	return sig
}

func generateBasicAggregateDataG2(t *testing.T) ([]*PublicKey, []*Signature, [][]byte) {
	msgs := make([][]byte, numAggregateG2)
	pks := make([]*PublicKey, numAggregateG2)
	sigs := make([]*Signature, numAggregateG2)
	ikm := make([]byte, 32)
	bls := NewSigBasic()

	for i := 0; i < numAggregateG2; i++ {
		readRand(ikm, t)
		pk, sk, err := bls.KeygenWithSeed(ikm)
		if err != nil {
			t.Errorf("Basic KeyGen failed")
		}
		msg := make([]byte, 20)
		readRand(msg, t)
		sig := generateBasicSignatureG2(sk, msg, t)
		msgs[i] = msg
		sigs[i] = sig
		pks[i] = pk
	}
	return pks, sigs, msgs
}

func TestBasicKeyGenG2Works(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasic()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}
}

func TestBasicKeyGenG2Fail(t *testing.T) {
	ikm := make([]byte, 10)
	readRand(ikm, t)
	bls := NewSigBasic()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err == nil {
		t.Errorf("Basic KeyGen succeeded when it should've failed")
	}
}

func TestBasicCustomDstG2(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasicWithDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_TEST")
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Basic Custom Dst KeyGen failed")
	}

	readRand(ikm, t)
	sig, err := bls.Sign(sk, ikm)

	if err != nil {
		t.Errorf("Basic Custom Dst Sign failed")
	}

	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Basic Custon Dst verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Basic Custom Dst verify succeeded when it should've failed.")
	}
}

func TestBasicSigningG2(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasic()
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	readRand(ikm, t)
	sig := generateBasicSignatureG2(sk, ikm, t)

	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Basic verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Basic verify succeeded when it should've failed.")
	}
}

func TestBasicSigningG2EmptyMessage(t *testing.T) {
	// So basic
	bls := NewSigBasic()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	// Sign an empty message
	_, err = bls.Sign(sk, []byte{})
	if err != nil {
		t.Errorf("Expected signing empty message to succeed: %v", err)
	}
}

func TestBasicSigningG2NilMessage(t *testing.T) {
	// So basic
	bls := NewSigBasic()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	// Sign an empty message
	_, err = bls.Sign(sk, nil)
	if err == nil {
		t.Errorf("Expected signing nil message to fail")
	}
}

func TestBasicAggregateVerifyG2Works(t *testing.T) {
	pks, sigs, msgs := generateBasicAggregateDataG2(t)
	bls := NewSigBasic()

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic AggregateVerify failed")
	}
}

func TestBasicAggregateVerifyG2BadPks(t *testing.T) {
	bls := NewSigBasic()
	pks, sigs, msgs := generateBasicAggregateDataG2(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic AggregateVerify failed")
	}

	pks[0] = pks[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic AggregateVerify succeeded when it should've failed")
	}

	// Try a zero key to make sure it doesn't crash
	g1 := bls12381.NewG1()
	pkValue := g1.New()
	pks[0] = &PublicKey{value: *pkValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic AggregateVerify succeeded with zero byte public key it should've failed")
	}

	// Try with base generator
	pkValue = g1.One()
	pks[0] = &PublicKey{value: *pkValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with the base generator public key it should've failed")
	}
}

func TestBasicAggregateVerifyG2BadSigs(t *testing.T) {
	bls := NewSigBasic()
	pks, sigs, msgs := generateBasicAggregateDataG2(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic aggregateVerify failed")
	}

	sigs[0] = sigs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded when it should've failed")
	}

	// Try a zero key to make sure it doesn't crash
	g2 := bls12381.NewG2()
	sigValue := g2.New()
	sigs[0] = &Signature{Value: *sigValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with zero byte signature it should've failed")
	}

	// Try with base generator
	sigValue = g2.One()
	sigs[0] = &Signature{Value: *sigValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with the base generator signature it should've failed")
	}
}

func TestBasicAggregateVerifyG2BadMsgs(t *testing.T) {
	bls := NewSigBasic()
	pks, sigs, msgs := generateBasicAggregateDataG2(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic aggregateVerify failed")
	}

	msgs[0] = msgs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded when it should've failed")
	}
}

func TestBasicThresholdKeygenBadInputs(t *testing.T) {
	bls := NewSigBasic()
	_, _, err := bls.ThresholdKeygen(0, 0)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
	_, _, err = bls.ThresholdKeygen(1, 0)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
	_, _, err = bls.ThresholdKeygen(3, 2)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
}

func TestBasicThresholdKeygen(t *testing.T) {
	bls := NewSigBasic()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	if len(sks) != 5 {
		t.Errorf("ThresholdKeygen did not produce enough shares")
	}
}

func TestBasicPartialSign(t *testing.T) {
	ikm := make([]byte, 32)
	bls := NewSigBasic()
	pk, sks, err := bls.ThresholdKeygenWithSeed(ikm, 2, 4)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	msg := make([]byte, 10)
	sig1, err := bls.PartialSign(sks[0], msg)
	if err != nil {
		t.Errorf("partialSign failed: %v", err)
	}
	sig2, err := bls.PartialSign(sks[1], msg)
	if err != nil {
		t.Errorf("partialSign failed: %v", err)
	}
	sig, err := bls.CombineSignatures(sig1, sig2)
	if err != nil {
		t.Errorf("CombineSignatures failed: %v", err)
	}

	if res, _ := bls.Verify(pk, msg, sig); !res {
		t.Errorf("Combined signature does not verify")
	}

	sig, err = bls.CombineSignatures(sig1)
	if err == nil {
		t.Errorf("CombineSignatures succeeded when it should've failed")
	}
	if res, _ := bls.Verify(pk, msg, sig); res {
		t.Errorf("Combined signature verify succeeded when it should've failed")
	}
}

// Ensure that duplicate partial signatures cannot be used to create a complete one
func TestBasicPartialDuplicateShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigBasic()
	pk1, sks1, err := bls.ThresholdKeygenWithSeed(ikm, 3, total)
	if err != nil {
		t.Errorf("ThresholdKeygen failed: %v", err)
	}

	// Generate partial signatures for both sets of keys
	msg := make([]byte, 10)
	sigs1 := make([]*PartialSignature, total)
	for i := range sks1 {
		sigs1[i], err = bls.PartialSign(sks1[i], msg)
		if err != nil {
			t.Errorf("PartialSign failed: %v", err)
		}
	}

	// Try combining duplicates from group 1
	sig, err := bls.CombineSignatures(sigs1[0], sigs1[0], sigs1[1], sigs1[1])
	if err == nil {
		t.Errorf("CombineSignatures expected to fail but succeeded")
	}
	// Signature shouldn't validate
	if res, _ := bls.Verify(pk1, msg, sig); res {
		t.Errorf("CombineSignatures worked with duplicate partial signatures")
	}
}

// Ensure that mixed partial signatures from distinct origins create invalid composite signatures
func TestBasicPartialMixupShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigBasic()
	pk1, sks1, err := bls.ThresholdKeygenWithSeed(ikm, 3, total)
	if err != nil {
		t.Errorf("ThresholdKeygen failed: %v", err)
	}
	for i := range ikm {
		ikm[i] = 1
	}
	pk2, sks2, err := bls.ThresholdKeygenWithSeed(ikm, 3, total)
	if err != nil {
		t.Errorf("ThresholdKeygen failed: %v", err)
	}

	// Generate partial signatures for both sets of keys
	msg := make([]byte, 10)
	sigs1 := make([]*PartialSignature, total)
	sigs2 := make([]*PartialSignature, total)
	for i := range sks1 {
		sigs1[i], err = bls.PartialSign(sks1[i], msg)
		if err != nil {
			t.Errorf("PartialSign failed: %v", err)
		}
		sigs2[i], err = bls.PartialSign(sks2[i], msg)
		if err != nil {
			t.Errorf("PartialSign failed: %v", err)
		}
	}

	// Try combining 2 from group 1 and 2 from group 2
	sig, err := bls.CombineSignatures(sigs1[0], sigs1[1], sigs2[2], sigs2[3])
	if err != nil {
		t.Errorf("CombineSignatures failed: %v", err)
	}
	// Signature shouldn't validate
	if res, _ := bls.Verify(pk1, msg, sig); res {
		t.Errorf("CombineSignatures worked with different shares of two secret keys for the same message")
	}
	if res, _ := bls.Verify(pk2, msg, sig); res {
		t.Errorf("CombineSignatures worked with different shares of two secret keys for the same message")
	}
	// Should error out due to duplicate identifiers
	_, err = bls.CombineSignatures(sigs1[0], sigs1[1], sigs2[0], sigs2[1])
	if err == nil {
		t.Errorf("CombineSignatures expected to fail but succeeded.")
	}
}

func TestIdentityPublicKey(t *testing.T) {
	bls := NewSigBasic()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
	msg := []byte{0, 0, 0, 0}
	sig, _ := bls.Sign(sk, msg)
	pk := PublicKey{value: *bls12381.NewG1().Zero()}
	if res, _ := bls.Verify(&pk, msg, sig); res {
		t.Errorf("Verify succeeded when the public key is the identity.")
	}
}

func TestThresholdSignTooHighAndLow(t *testing.T) {
	bls := NewSigBasic()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("ThresholdKeygen failed: %v", err)
	}
	msg := make([]byte, 10)

	ps, err := bls.PartialSign(sks[0], msg)
	if err != nil {
		t.Errorf("PartialSign failed: %v", err)
	}

	_, err = bls.CombineSignatures(ps)
	if err == nil {
		t.Errorf("CombinSignatures succeeded when it should've failed")
	}

	pss := make([]*PartialSignature, 256)

	_, err = bls.CombineSignatures(pss...)
	if err == nil {
		t.Errorf("CombinSignatures succeeded when it should've failed")
	}
}
