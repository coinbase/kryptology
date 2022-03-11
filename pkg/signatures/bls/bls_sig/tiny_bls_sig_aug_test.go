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

func generateAugSignatureG1(sk *SecretKey, msg []byte, t *testing.T) *SignatureVt {
	bls := NewSigAugVt()
	sig, err := bls.Sign(sk, msg)
	if err != nil {
		t.Errorf("Aug Sign failed")
	}
	return sig
}

func generateAugAggregateDataG1(t *testing.T) ([]*PublicKeyVt, []*SignatureVt, [][]byte) {
	msgs := make([][]byte, numAggregateG1)
	pks := make([]*PublicKeyVt, numAggregateG1)
	sigs := make([]*SignatureVt, numAggregateG1)
	ikm := make([]byte, 32)
	bls := NewSigAugVt()

	for i := 0; i < numAggregateG1; i++ {
		readRand(ikm, t)
		pk, sk, err := bls.KeygenWithSeed(ikm)
		if err != nil {
			t.Errorf("Aug KeyGen failed")
		}
		msg := make([]byte, 20)
		readRand(msg, t)
		sig := generateAugSignatureG1(sk, msg, t)
		msgs[i] = msg
		sigs[i] = sig
		pks[i] = pk
	}
	return pks, sigs, msgs
}

func TestAugKeyGenG1Works(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigAugVt()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Aug KeyGen failed")
	}
}

func TestAugKeyGenG1Fail(t *testing.T) {
	ikm := make([]byte, 10)
	readRand(ikm, t)
	bls := NewSigAugVt()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err == nil {
		t.Errorf("Aug KeyGen succeeded when it should've failed")
	}
}

func TestAugCustomDstG1(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigAugVtWithDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_TEST")
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Aug Custom Dst KeyGen failed")
	}

	readRand(ikm, t)
	sig, err := bls.Sign(sk, ikm)

	if err != nil {
		t.Errorf("Aug Custom Dst Sign failed")
	}

	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Aug Custom Dst Verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Aug Custom Dst Verify succeeded when it should've failed.")
	}
}

func TestAugSigningG1(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigAugVt()
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Aug KeyGen failed")
	}

	readRand(ikm, t)
	sig := generateAugSignatureG1(sk, ikm, t)

	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Aug Verify failed")
	}

	ikm[0] += 1
	if res, _ := bls.Verify(pk, ikm, sig); res {
		t.Errorf("Aug Verify succeeded when it should've failed.")
	}
}

func TestAugAggregateVerifyG1Works(t *testing.T) {
	pks, sigs, msgs := generateAugAggregateDataG1(t)
	bls := NewSigAugVt()

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Aug AggregateVerify failed")
	}
}

func TestAugAggregateVerifyG1BadPks(t *testing.T) {
	bls := NewSigAugVt()
	pks, sigs, msgs := generateAugAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Aug AggregateVerify failed")
	}

	pks[0] = pks[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug AggregateVerify succeeded when it should've failed")
	}

	// Try a zero key to make sure it doesn't crash
	pkValue := new(bls12381.G2).Identity()
	pks[0] = &PublicKeyVt{value: *pkValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug AggregateVerify succeeded with zero byte public key it should've failed")
	}

	// Try with base generator
	pkValue.Generator()
	pks[0] = &PublicKeyVt{value: *pkValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug aggregateVerify succeeded with the base generator public key it should've failed")
	}
}

func TestAugAggregateVerifyG1BadSigs(t *testing.T) {
	bls := NewSigAugVt()
	pks, sigs, msgs := generateAugAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Aug aggregateVerify failed")
	}

	sigs[0] = sigs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug aggregateVerify succeeded when it should've failed")
	}

	// Try a zero signature to make sure it doesn't crash
	sigValue := new(bls12381.G1).Identity()
	sigs[0] = &SignatureVt{value: *sigValue}

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug aggregateVerify succeeded with zero byte signature it should've failed")
	}

	// Try with base generator
	sigValue.Generator()
	sigs[0] = &SignatureVt{value: *sigValue}
	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug aggregateVerify succeeded with the base generator signature it should've failed")
	}
}

func TestAugAggregateVerifyG1BadMsgs(t *testing.T) {
	bls := NewSigAugVt()
	pks, sigs, msgs := generateAugAggregateDataG1(t)

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); !res {
		t.Errorf("Aug aggregateVerify failed")
	}

	// Test len(pks) != len(msgs)
	if res, _ := bls.AggregateVerify(pks, msgs[0:8], sigs); res {
		t.Errorf("Aug aggregateVerify succeeded when it should've failed")
	}

	msgs[0] = msgs[1]

	if res, _ := bls.AggregateVerify(pks, msgs, sigs); res {
		t.Errorf("Aug aggregateVerify succeeded when it should've failed")
	}
}

func TestAugAggregateVerifyG1DupMsg(t *testing.T) {
	bls := NewSigAugVt()

	// Only two messages but repeated
	messages := make([][]byte, numAggregateG1)
	messages[0] = []byte("Yes")
	messages[1] = []byte("No")
	for i := 2; i < numAggregateG1; i++ {
		messages[i] = messages[i%2]
	}

	pks := make([]*PublicKeyVt, numAggregateG1)
	sigs := make([]*SignatureVt, numAggregateG1)

	ikm := make([]byte, 32)
	for i := 0; i < numAggregateG1; i++ {
		readRand(ikm, t)
		pk, sk, err := bls.KeygenWithSeed(ikm)
		if err != nil {
			t.Errorf("Aug KeyGen failed")
		}

		sig := generateAugSignatureG1(sk, messages[i], t)
		pks[i] = pk
		sigs[i] = sig
	}

	if res, _ := bls.AggregateVerify(pks, messages, sigs); !res {
		t.Errorf("Aug aggregateVerify failed for duplicate messages")
	}
}

func TestBlsAugG1KeyGen(t *testing.T) {
	bls := NewSigAugVt()
	_, _, err := bls.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
}

func TestAugVtThresholdKeygenBadInputs(t *testing.T) {
	bls := NewSigAugVt()
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

func TestAugVtThresholdKeygen(t *testing.T) {
	bls := NewSigAugVt()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	if len(sks) != 5 {
		t.Errorf("ThresholdKeygen did not produce enough shares")
	}
}

func TestAugPartialSignVt(t *testing.T) {
	ikm := make([]byte, 32)
	bls := NewSigAugVt()
	pk, sks, err := bls.ThresholdKeygenWithSeed(ikm, 2, 4)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	msg := make([]byte, 10)
	sig1, err := bls.PartialSign(sks[0], pk, msg)
	if err != nil {
		t.Errorf("partialSign failed: %v", err)
	}
	sig2, err := bls.PartialSign(sks[1], pk, msg)
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
		t.Errorf("CombineSignatures failed: %v", err)
	}
	if res, _ := bls.Verify(pk, msg, sig); res {
		t.Errorf("Combined signature verify succeeded when it should've failed")
	}
}

// Ensure that mixed partial signatures from distinct origins create invalid composite signatures
func TestAugVtPartialMixupShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigAugVt()
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
		sigs1[i], err = bls.PartialSign(sks1[i], pk1, msg)
		if err != nil {
			t.Errorf("PartialSign failed: %v", err)
		}
		sigs2[i], err = bls.PartialSign(sks2[i], pk2, msg)
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

func TestEmptyMessageAugPartialSignVt(t *testing.T) {
	bls := NewSigAugVt()
	pk, sks, err := bls.ThresholdKeygen(5, 6)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}

	// Sign an empty message
	_, err = bls.PartialSign(sks[0], pk, []byte{})
	if err == nil {
		t.Errorf("Expected partial sign to fail on empty message")
	}
}

func TestNilMessageAugPartialSignVt(t *testing.T) {
	bls := NewSigAugVt()
	pk, sks, err := bls.ThresholdKeygen(5, 6)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}

	// Sign nil message
	_, err = bls.PartialSign(sks[0], pk, nil)
	if err == nil {
		t.Errorf("Expected partial signing to fail on nil message")
	}
}
