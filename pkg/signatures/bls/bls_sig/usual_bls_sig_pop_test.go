//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls_sig

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
)

const numAggregateG2 = 10

func TestGetPublicKeyG1(t *testing.T) {
	sk := genSecretKey(t)
	pk := genPublicKey(sk, t)
	actual := marshalStruct(pk, t)
	expected := []byte{166, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166, 52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178, 0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89}
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected GetPublicKey to pass but failed.")
	}
}

func testSignG2(message []byte, t *testing.T) {
	sk := genSecretKey(t)
	sig := genSignature(sk, message, t)
	pk := genPublicKey(sk, t)

	bls := NewSigPop()

	if res, err := bls.Verify(pk, message, sig); !res {
		t.Errorf("createSignature failed when it should've passed: %v", err)
	}
}

func TestSignG2EmptyMessage(t *testing.T) {
	bls := NewSigPop()
	sk := genSecretKey(t)
	sig, _ := bls.Sign(sk, nil)
	pk := genPublicKey(sk, t)

	if res, _ := bls.Verify(pk, nil, sig); res {
		t.Errorf("createSignature succeeded when it should've failed")
	}

	message := []byte{}
	sig = genSignature(sk, message, t)

	if res, err := bls.Verify(pk, message, sig); !res {
		t.Errorf("create and verify failed on empty message: %v", err)
	}
}

func TestSignG2OneByteMessage(t *testing.T) {
	message := []byte{1}
	testSignG2(message, t)
}

func TestSignG2LargeMessage(t *testing.T) {
	message := make([]byte, 1048576)
	testSignG2(message, t)
}

func TestSignG2RandomMessage(t *testing.T) {
	message := make([]byte, 65537)
	readRand(message, t)
	testSignG2(message, t)
}

func TestSignG2BadMessage(t *testing.T) {
	message := make([]byte, 1024)
	sk := genSecretKey(t)
	sig := genSignature(sk, message, t)
	pk := genPublicKey(sk, t)
	message = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	bls := NewSigPop()

	if res, _ := bls.Verify(pk, message, sig); res {
		t.Errorf("Expected signature to not verify")
	}
}

func TestBadConversionsG2(t *testing.T) {
	sk := genSecretKey(t)
	message := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	sig := genSignature(sk, message, t)
	pk := genPublicKey(sk, t)

	bls := NewSigPop()

	if res, _ := bls.Verify(pk, message, sig); !res {
		t.Errorf("Signature should be valid")
	}
	if res, _ := sig.verify(pk, message, blsSignaturePopDst); !res {
		t.Errorf("Signature should be valid")
	}

	// Convert public key to signature in G2
	sig2 := new(SignatureVt)
	err := sig2.UnmarshalBinary(marshalStruct(pk, t))
	if err != nil {
		t.Errorf("Should be able to convert to signature in G2")
	}
	pk2 := new(PublicKeyVt)
	err = pk2.UnmarshalBinary(marshalStruct(sig, t))
	if err != nil {
		t.Errorf("Should be able to convert to public key in G1")
	}

	if res, _ := pk2.verifySignatureVt(message, sig2, blsSignaturePopDst); res {
		t.Errorf("The signature shouldn't verify")
	}
}

func TestAggregatePublicKeysG1(t *testing.T) {
	pks := []*PublicKey{}
	ikm := make([]byte, 32)
	for i := 0; i < 20; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		pk := genPublicKey(sk, t)
		pks = append(pks, pk)
	}
	apk1, err := aggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	rand.Seed(1234567890)
	rand.Shuffle(len(pks), func(i, j int) { pks[i], pks[j] = pks[j], pks[i] })
	apk2, err := aggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(apk1, t), marshalStruct(apk2, t)) {
		t.Errorf("Aggregated public keys should be equal")
	}
	rand.Shuffle(len(pks), func(i, j int) { pks[i], pks[j] = pks[j], pks[i] })
	apk1, err = aggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(apk1, t), marshalStruct(apk2, t)) {
		t.Errorf("Aggregated public keys should be equal")
	}
}

func TestAggregateSignaturesG2(t *testing.T) {
	var sigs []*Signature
	ikm := make([]byte, 32)
	for i := 0; i < 20; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		sig := genSignature(sk, ikm, t)
		sigs = append(sigs, sig)
	}
	asig1, err := aggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	rand.Seed(1234567890)
	rand.Shuffle(len(sigs), func(i, j int) { sigs[i], sigs[j] = sigs[j], sigs[i] })
	asig2, err := aggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(asig1, t), marshalStruct(asig2, t)) {
		t.Errorf("Aggregated signatures should be equal")
	}
	rand.Shuffle(len(sigs), func(i, j int) { sigs[i], sigs[j] = sigs[j], sigs[i] })
	asig1, err = aggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(asig1, t), marshalStruct(asig2, t)) {
		t.Errorf("Aggregated signatures should be equal")
	}
}

func initAggregatedTestValuesG2(messages [][]byte, t *testing.T) ([]*PublicKey, []*Signature) {
	pks := []*PublicKey{}
	sigs := []*Signature{}
	ikm := make([]byte, 32)
	for i := 0; i < numAggregateG2; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		sig := genSignature(sk, messages[i%len(messages)], t)
		sigs = append(sigs, sig)
		pk := genPublicKey(sk, t)
		pks = append(pks, pk)
	}
	return pks, sigs
}

func TestAggregatedFunctionalityG2(t *testing.T) {
	message := make([]byte, 20)
	messages := make([][]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG2(messages, t)

	bls := NewSigPop()
	asig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	apk, err := bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if res, _ := bls.VerifyMultiSignature(apk, message, asig); !res {
		t.Errorf("Should verify aggregated signatures with same message")
	}
	if res, _ := asig.verify(apk, message, blsSignaturePopDst); !res {
		t.Errorf("MultiSignature.verify failed.")
	}
	if res, _ := apk.verify(message, asig, blsSignaturePopDst); !res {
		t.Errorf("MultiPublicKey.verify failed.")
	}
}

func TestBadAggregatedFunctionalityG2(t *testing.T) {
	message := make([]byte, 20)
	messages := make([][]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG2(messages, t)

	bls := NewSigPop()

	apk, err := bls.AggregatePublicKeys(pks[2:]...)
	if err != nil {
		t.Errorf("%v", err)
	}
	asig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}

	if res, _ := bls.VerifyMultiSignature(apk, message, asig); res {
		t.Errorf("Should not verify aggregated signatures with same message when some public keys are missing")
	}

	apk, err = bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	asig, err = bls.AggregateSignatures(sigs[2:]...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if res, _ := bls.VerifyMultiSignature(apk, message, asig); res {
		t.Errorf("Should not verify aggregated signatures with same message when some signatures are missing")
	}

	asig, err = bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}

	badmsg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	if res, _ := bls.VerifyMultiSignature(apk, badmsg, asig); res {
		t.Errorf("Should not verify aggregated signature with bad message")
	}
}

func TestAggregateVerifyG2Pass(t *testing.T) {
	messages := make([][]byte, numAggregateG2)
	for i := 0; i < numAggregateG2; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); !res {
		t.Errorf("Expected aggregateVerify to pass but failed")
	}
}

func TestAggregateVerifyG2MsgSigCntMismatch(t *testing.T) {
	messages := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}

	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); res {
		t.Errorf("Expected AggregateVerifyG2 to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG2FailDupMsg(t *testing.T) {
	messages := make([][]byte, 10)
	for i := 0; i < 9; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	// Duplicate message
	messages[9] = messages[0]
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); res {
		t.Errorf("Expected aggregateVerify to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG2FailIncorrectMsg(t *testing.T) {
	messages := make([][]byte, 10)
	for i := 0; i < 9; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	// Duplicate message
	messages[9] = messages[0]
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	if res, _ := bls.AggregateVerify(pks[2:], messages[2:], sigs); res {
		t.Errorf("Expected aggregateVerify to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG2OneMsg(t *testing.T) {
	messages := make([][]byte, 1)
	messages[0] = make([]byte, 20)
	sk := genSecretKey(t)
	sig := genSignature(sk, messages[0], t)
	pk := genPublicKey(sk, t)
	bls := NewSigPop()
	// Should be the same as verifySignature
	if res, _ := bls.AggregateVerify([]*PublicKey{pk}, messages, []*Signature{sig}); !res {
		t.Errorf("Expected AggregateVerifyG2OneMsg to pass but failed")
	}
}

func TestVerifyG2Mutability(t *testing.T) {
	//verify should not change any inputs
	ikm := make([]byte, 32)
	ikm_copy := make([]byte, 32)
	readRand(ikm, t)
	copy(ikm_copy, ikm)
	bls := NewSigPop()
	pk, sk, err := bls.KeygenWithSeed(ikm)

	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPop.KeygenWithSeed modifies ikm")
	}
	if err != nil {
		t.Errorf("Expected KeygenWithSeed to succeed but failed.")
	}
	sig, err := bls.Sign(sk, ikm)
	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPop.Sign modifies message")
	}
	if err != nil {
		t.Errorf("SigPop.KeygenWithSeed to succeed but failed.")
	}
	sigCopy := marshalStruct(sig, t)
	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Expected verify to succeed but failed.")
	}
	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPop.verify modifies message")
	}
	if !bytes.Equal(sigCopy, marshalStruct(sig, t)) {
		t.Errorf("SigPop.verify modifies signature")
	}
}

func TestPublicKeyG1FromBadBytes(t *testing.T) {
	pk := make([]byte, 32)
	err := new(PublicKey).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG1FromBytes to fail but passed")
	}
	// All zeros
	pk = make([]byte, PublicKeySize)
	// See https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
	// 1 << 7 == compressed
	// 1 << 6 == infinity or zero
	pk[0] = 0xc0
	err = new(PublicKey).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG1FromBytes to fail but passed")
	}
	sk := genSecretKey(t)
	pk1, err := sk.GetPublicKey()
	if err != nil {
		t.Errorf("Expected GetPublicKey to pass but failed.")
	}
	out := marshalStruct(pk1, t)
	out[3] += 1
	err = new(PublicKey).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG1FromBytes to fail but passed")
	}
}

func TestSignatureG2FromBadBytes(t *testing.T) {
	sig := make([]byte, 32)
	err := new(Signature).UnmarshalBinary(sig)
	if err == nil {
		t.Errorf("Expected SignatureG2FromBytes to fail but passed")
	}
	// All zeros
	sig = make([]byte, SignatureSize)
	// See https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
	// 1 << 7 == compressed
	// 1 << 6 == infinity or zero
	sig[0] = 0xc0
	err = new(Signature).UnmarshalBinary(sig)
	if err == nil {
		t.Errorf("Expected SignatureG2FromBytes to fail but passed")
	}
}

func TestBadSecretKeyG2(t *testing.T) {
	sk := &SecretKey{value: bls12381.Bls12381FqNew()}
	pk, err := sk.GetPublicKey()
	if err == nil {
		t.Errorf("Expected GetPublicKey to fail with 0 byte secret key but passed: %v", pk)
	}
	_ = sk.UnmarshalBinary(sk.value.Params.BiModulus.Bytes())
	pk, err = sk.GetPublicKey()
	if err == nil {
		t.Errorf("Expected GetPublicKey to fail with secret key with Q but passed: %v", pk)
	}

	err = sk.UnmarshalBinary([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if err == nil {
		t.Errorf("Expected SecretKeyFromBytes to fail with not enough bytes but passed: %v", pk)
	}

	err = sk.UnmarshalBinary(make([]byte, 32))
	if err == nil {
		t.Errorf("Expected SecretKeyFromBytes to fail with all zeros but passed: %v", pk)
	}
}

func TestProofOfPossessionG2Works(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigPop()
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Key gen failed but should've succeeded")
	}
	pop, err := bls.PopProve(sk)
	if err != nil {
		t.Errorf("PopProve failed but should've succeeded")
	}
	if res, _ := bls.PopVerify(pk, pop); !res {
		t.Errorf("PopVerify failed but should've succeeded")
	}
}

func TestProofOfPossessionG2FromBadKey(t *testing.T) {
	ikm := make([]byte, 32)
	value := new(big.Int)
	value.SetBytes(ikm)
	sk := SecretKey{value: bls12381.Bls12381FqNew().SetBigInt(value)}
	_, err := sk.createProofOfPossession(blsSignaturePopDst)
	if err == nil {
		t.Errorf("createProofOfPossession should've failed but succeeded.")
	}
}

func TestProofOfPossessionG2BytesWorks(t *testing.T) {
	sk := genSecretKey(t)
	pop, err := sk.createProofOfPossession(blsSignaturePopDst)
	if err != nil {
		t.Errorf("CreateProofOfPossesionG2 failed but shouldn've succeeded.")
	}
	out := marshalStruct(pop, t)
	if len(out) != ProofOfPossessionSize {
		t.Errorf("ProofOfPossessionBytes incorrect size: expected %v, got %v", ProofOfPossessionSize, len(out))
	}
	pop2 := new(ProofOfPossession)
	err = pop2.UnmarshalBinary(out)
	if err != nil {
		t.Errorf("ProofOfPossession.UnmarshalBinary failed: %v", err)
	}
	out2 := marshalStruct(pop2, t)
	if !bytes.Equal(out, out2) {
		t.Errorf("ProofOfPossession.UnmarshalBinary failed, not equal when deserialized")
	}
}

func TestProofOfPossessionG2BadBytes(t *testing.T) {
	zeros := make([]byte, ProofOfPossessionSize)
	temp := new(ProofOfPossession)
	err := temp.UnmarshalBinary(zeros)
	if err == nil {
		t.Errorf("ProofOfPossession.UnmarshalBinary shouldn've failed but succeeded.")
	}
}

func TestProofOfPossessionG2Fails(t *testing.T) {
	sk := genSecretKey(t)
	pop, err := sk.createProofOfPossession(blsSignaturePopDst)
	if err != nil {
		t.Errorf("Expected createProofOfPossession to succeed but failed.")
	}

	ikm := make([]byte, 32)
	readRand(ikm, t)
	sk = genRandSecretKey(ikm, t)
	bad, err := sk.GetPublicKey()
	if err != nil {
		t.Errorf("Expected PublicKeyG1FromBytes to succeed but failed: %v", err)
	}
	if res, _ := pop.verify(bad, blsSignaturePopDst); res {
		t.Errorf("Expected ProofOfPossession verify to fail but succeeded.")
	}
}

func TestMultiSigG2Bytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	_, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	msig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	msigBytes := marshalStruct(msig, t)
	if len(msigBytes) != SignatureSize {
		t.Errorf("Invalid multi-sig length. Expected %d bytes, found %d", SignatureSize, len(msigBytes))
	}
	msig2 := new(MultiSignature)
	err = msig2.UnmarshalBinary(msigBytes)
	if err != nil {
		t.Errorf("MultiSignatureG2FromBytes failed with %v", err)
	}
	msigBytes2 := marshalStruct(msig2, t)

	if !bytes.Equal(msigBytes, msigBytes2) {
		t.Errorf("Bytes methods not equal.")
	}
}

func TestMultiSigG2BadBytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	_, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	msig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	msigBytes := marshalStruct(msig, t)
	if len(msigBytes) != SignatureSize {
		t.Errorf("Invalid multi-sig length. Expected %d bytes, found %d", SignatureSize, len(msigBytes))
	}
	msigBytes[0] = 0
	temp := new(MultiSignature)
	err = temp.UnmarshalBinary(msigBytes)
	if err == nil {
		t.Errorf("MultiSignatureG2FromBytes should've failed but succeeded")
	}
	msigBytes = make([]byte, SignatureSize)
	err = temp.UnmarshalBinary(msigBytes)
	if err == nil {
		t.Errorf("MultiSignatureG2FromBytes should've failed but succeeded")
	}
}

func TestMultiPubkeyG1Bytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	pks, _ := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	apk, err := bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	apkBytes := marshalStruct(apk, t)
	if len(apkBytes) != PublicKeySize {
		t.Errorf("MultiPublicKey has an incorrect size")
	}
	apk2 := new(MultiPublicKey)
	err = apk2.UnmarshalBinary(apkBytes)
	if err != nil {
		t.Errorf("MultiPublicKey.UnmarshalBinary failed with %v", err)
	}
	apk2Bytes := marshalStruct(apk2, t)
	if !bytes.Equal(apkBytes, apk2Bytes) {
		t.Errorf("Bytes methods not equal.")
	}
}

func TestMultiPubkeyG1BadBytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	pks, _ := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	apk, err := bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	apkBytes := marshalStruct(apk, t)
	if len(apkBytes) != PublicKeySize {
		t.Errorf("MultiPublicKey has an incorrect size")
	}
	apkBytes[0] = 0
	temp := new(MultiPublicKey)
	err = temp.UnmarshalBinary(apkBytes)
	if err == nil {
		t.Errorf("MultiPublicKey.UnmarshalBinary should've failed but succeeded")
	}
	apkBytes = make([]byte, PublicKeySize)
	err = temp.UnmarshalBinary(apkBytes)
	if err == nil {
		t.Errorf("MultiPublicKey.UnmarshalBinary should've failed but succeeded")
	}
}

func TestFastAggregateVerifyG2Works(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	asigs, _ := aggregateSignatures(sigs...)
	bls := NewSigPop()
	if res, _ := bls.FastAggregateVerify(pks, message, asigs); !res {
		t.Errorf("FastAggregateVerify failed.")
	}
}

func TestFastAggregateVerifyConstituentG2Works(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	if res, _ := bls.FastAggregateVerifyConstituent(pks, message, sigs); !res {
		t.Errorf("FastAggregateVerify failed.")
	}
}

func TestFastAggregateVerifyG2Fails(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG2(messages, t)
	bls := NewSigPop()
	message[0] = 1
	if res, _ := bls.FastAggregateVerifyConstituent(pks, message, sigs); res {
		t.Errorf("FastAggregateVerify verified when it should've failed.")
	}
}

func TestCustomPopDstG2Works(t *testing.T) {
	bls, _ := NewSigPopWithDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_TEST",
		"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_TEST")
	msg := make([]byte, 20)
	ikm := make([]byte, 32)
	pk, sk, err := bls.KeygenWithSeed(ikm)
	if err != nil {
		t.Errorf("Couldn't create custom dst keys: %v", err)
	}
	sig, err := bls.Sign(sk, msg)
	if err != nil {
		t.Errorf("Couldn't sign with custom dst: %v", err)
	}
	if res, _ := bls.Verify(pk, msg, sig); !res {
		t.Errorf("verify fails with custom dst")
	}

	pks := make([]*PublicKey, 10)
	sigs := make([]*Signature, 10)
	pks[0] = pk
	sigs[0] = sig
	for i := 1; i < 10; i++ {
		readRand(ikm, t)
		pkt, skt, err := bls.KeygenWithSeed(ikm)
		if err != nil {
			t.Errorf("Couldn't create custom dst keys: %v", err)
		}
		sigt, err := bls.Sign(skt, msg)
		if err != nil {
			t.Errorf("Couldn't sign with custom dst: %v", err)
		}
		pks[i] = pkt
		sigs[i] = sigt
	}

	if res, _ := bls.FastAggregateVerifyConstituent(pks, msg, sigs); !res {
		t.Errorf("FastAggregateVerify failed with custom dst")
	}

	pop, err := bls.PopProve(sk)
	if err != nil {
		t.Errorf("PopProve failed with custom dst")
	}

	if res, _ := bls.PopVerify(pk, pop); !res {
		t.Errorf("PopVerify failed with custom dst")
	}
}

func TestBlsPopG2KeyGenWithSeed(t *testing.T) {
	ikm := []byte("Not enough bytes")
	bls := NewSigPop()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err == nil {
		t.Errorf("Expected KeygenWithSeed to fail but succeeded")
	}
}

func TestBlsPopG2KeyGen(t *testing.T) {
	bls := NewSigPop()
	_, _, err := bls.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
}

func TestPopThresholdKeygenBadInputs(t *testing.T) {
	bls := NewSigPop()
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

func TestPopThresholdKeygen(t *testing.T) {
	bls := NewSigPop()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	if len(sks) != 5 {
		t.Errorf("ThresholdKeygen did not produce enough shares")
	}
}
func TestPopPartialSign(t *testing.T) {
	ikm := make([]byte, 32)
	bls := NewSigPop()
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
func TestPopPartialMixupShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigPop()
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

func TestNewSigEth2KeyGen(t *testing.T) {
	eth2 := NewSigEth2()
	_, _, err := eth2.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
}

func TestSigEth2SignRoundTrip(t *testing.T) {
	eth2 := NewSigEth2()
	pop := NewSigPop()
	eth2Pk, eth2Sk, err := eth2.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}

	sig, err := pop.Sign(eth2Sk, []byte{0, 0})
	if err != nil {
		t.Errorf("Sign failed: %v", err)
	}
	if ok, err := eth2.Verify(eth2Pk, []byte{0, 0}, sig); err != nil || !ok {
		t.Errorf("Verify failed: %v", err)
	}
}
