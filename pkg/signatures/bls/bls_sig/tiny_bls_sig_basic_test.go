//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls_sig

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
)

func generateBasicSignatureG1(sk *SecretKey, msg []byte, t *testing.T) *SignatureVt {
	bls := NewSigBasicVt()
	sig, err := bls.Sign(sk, msg)
	if err != nil {
		t.Errorf("Basic Sign failed")
	}
	return sig
}

func generateBasicAggregateDataG1(t *testing.T) ([]*PublicKeyVt, []*SignatureVt, [][]byte) {
	msgs := make([][]byte, numAggregateG1)
	pks := make([]*PublicKeyVt, numAggregateG1)
	sigs := make([]*SignatureVt, numAggregateG1)
	ikm := make([]byte, 32)
	bls := NewSigBasicVt()

	for i := 0; i < numAggregateG1; i++ {
		readRand(ikm, t)
		pk, sk, err := bls.KeygenWithSeed(ikm)
		if err != nil {
			t.Errorf("Basic KeyGen failed")
		}
		msg := make([]byte, 20)
		readRand(msg, t)
		sig := generateBasicSignatureG1(sk, msg, t)
		msgs[i] = msg
		sigs[i] = sig
		pks[i] = pk
	}
	return pks, sigs, msgs
}

func TestBasicKeyGenG1Works(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasicVt()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}
}

func TestBasicKeyGenG1Fail(t *testing.T) {
	ikm := make([]byte, 10)
	readRand(ikm, t)
	bls := NewSigBasicVt()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err == nil {
		t.Errorf("Basic KeyGen succeeded when it should've failed")
	}
}

func TestBasicCustomDstG1(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasicVtWithDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_TEST")
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
		t.Errorf("Basic Custon Dst Verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Basic Custom Dst Verify succeeded when it should've failed.")
	}
}

func TestBasicSigningG1(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigBasicVt()
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	readRand(ikm, t)
	sig := generateBasicSignatureG1(sk, ikm, t)

	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Basic Verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Basic Verify succeeded when it should've failed.")
	}
}

func TestBasicSigningEmptyMessage(t *testing.T) {
	bls := NewSigBasicVt()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	// Sign an empty message
	_, err = bls.Sign(sk, []byte{})
	if err != nil {
		t.Errorf("Expected signing message to succeed: %v", err)
	}
}

func TestBasicSigningNilMessage(t *testing.T) {
	bls := NewSigBasicVt()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Basic KeyGen failed")
	}

	// Sign nil message
	_, err = bls.Sign(sk, nil)
	if err == nil {
		t.Errorf("Expected signing empty message to fail")
	}
}

func TestBasicAggregateVerifyG1Works(t *testing.T) {
	pks, sigs, msgs := generateBasicAggregateDataG1(t)
	bls := NewSigBasicVt()

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic AggregateVerify failed")
	}
}

func TestBasicAggregateVerifyG1BadPks(t *testing.T) {
	bls := NewSigBasicVt()
	pks, sigs, msgs := generateBasicAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic aggregateVerify failed")
	}

	pks[0] = pks[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded when it should've failed")
	}

	// Try a zero key to make sure it doesn't crash
	pkValue := new(bls12381.G2).Identity()
	pks[0] = &PublicKeyVt{value: *pkValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with zero byte public key it should've failed")
	}

	// Try with base generator
	pkValue.Generator()
	pks[0] = &PublicKeyVt{value: *pkValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with the base generator public key it should've failed")
	}
}

func TestBasicAggregateVerifyG1BadSigs(t *testing.T) {
	bls := NewSigBasicVt()
	pks, sigs, msgs := generateBasicAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic aggregateVerify failed")
	}

	sigs[0] = sigs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded when it should've failed")
	}

	// Try a zero key to make sure it doesn't crash
	g1 := new(bls12381.G1).Identity()
	sigValue := g1.Identity()
	sigs[0] = &SignatureVt{value: *sigValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with zero byte signature it should've failed")
	}

	// Try with base generator
	sigValue = g1.Generator()
	sigs[0] = &SignatureVt{value: *sigValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded with the base generator signature it should've failed")
	}
}

func TestBasicAggregateVerifyG1BadMsgs(t *testing.T) {
	bls := NewSigBasicVt()
	pks, sigs, msgs := generateBasicAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Basic aggregateVerify failed")
	}

	msgs[0] = msgs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Basic aggregateVerify succeeded when it should've failed")
	}
}

func TestBasicVtThresholdKeygenBadInputs(t *testing.T) {
	bls := NewSigBasicVt()
	_, _, err := bls.ThresholdKeygen(0, 0)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
	_, _, err = bls.ThresholdKeygen(0, 1)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
	_, _, err = bls.ThresholdKeygen(3, 2)
	if err == nil {
		t.Errorf("ThresholdKeygen should've failed but succeeded")
	}
}

func TestBasicVtThresholdKeygen(t *testing.T) {
	bls := NewSigBasicVt()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
	if len(sks) != 5 {
		t.Errorf("ThresholdKeygen did not produce enough shares")
	}
}

func TestBasicPartialSignVt(t *testing.T) {
	ikm := make([]byte, 32)
	bls := NewSigBasicVt()
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

// Ensure that mixed partial signatures from distinct origins create invalid composite signatures
func TestBasicVtPartialMixupShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigBasicVt()
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
	sigs1 := make([]*PartialSignatureVt, total)
	sigs2 := make([]*PartialSignatureVt, total)
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

func TestIdentityPublicKeyVt(t *testing.T) {
	bls := NewSigBasicVt()
	_, sk, err := bls.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
	msg := []byte{0, 0, 0, 0}
	sig, _ := bls.Sign(sk, msg)
	pk := PublicKeyVt{value: *new(bls12381.G2).Identity()}
	if res, _ := bls.Verify(&pk, msg, sig); res {
		t.Errorf("Verify succeeded when the public key is the identity.")
	}
}

func TestThresholdSignTooHighAndLowVt(t *testing.T) {
	bls := NewSigBasicVt()
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

	pss := make([]*PartialSignatureVt, 256)

	_, err = bls.CombineSignatures(pss...)
	if err == nil {
		t.Errorf("CombinSignatures succeeded when it should've failed")
	}
}
