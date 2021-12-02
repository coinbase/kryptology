package bls_sig

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
)

const numAggregateG1 = 10

func TestGetPublicKeyG2(t *testing.T) {
	sk := genSecretKey(t)
	pk := genPublicKeyVt(sk, t)
	actual := marshalStruct(pk, t)
	expected := []byte{175, 76, 33, 103, 184, 172, 12, 111, 24, 87, 84, 61, 243, 82, 99, 76, 131, 95, 171, 237, 145, 143, 7, 93, 205, 148, 104, 29, 153, 103, 187, 206, 112, 223, 252, 198, 102, 41, 38, 244, 228, 223, 102, 16, 216, 152, 231, 250, 7, 111, 90, 98, 194, 244, 101, 251, 69, 130, 11, 209, 41, 210, 133, 105, 217, 179, 190, 1, 6, 155, 135, 2, 168, 249, 253, 41, 59, 87, 8, 49, 231, 198, 142, 30, 186, 44, 175, 17, 198, 63, 210, 176, 237, 171, 11, 127}
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected GetPublicKeyVt to pass but failed.")
	}
}

func testSignG1(message []byte, t *testing.T) {
	sk := genSecretKey(t)
	sig := genSignatureVt(sk, message, t)
	pk := genPublicKeyVt(sk, t)

	bls := NewSigPopVt()

	if res, _ := bls.Verify(pk, message, sig); !res {
		t.Errorf("createSignatureVt failed when it should've passed.")
	}
}

func TestSignG1EmptyNilMessage(t *testing.T) {
	sk := genSecretKey(t)
	bls := NewSigPopVt()
	sig, _ := bls.Sign(sk, nil)
	pk := genPublicKeyVt(sk, t)

	if res, _ := bls.Verify(pk, nil, sig); res {
		t.Errorf("createSignature succeeded when it should've failed")
	}

	message := []byte{}
	sig = genSignatureVt(sk, message, t)

	if res, err := bls.Verify(pk, message, sig); !res {
		t.Errorf("create and verify failed on empty message: %v", err)
	}
}

func TestSignG1OneByteMessage(t *testing.T) {
	message := []byte{1}
	testSignG1(message, t)
}

func TestSignG1LargeMessage(t *testing.T) {
	message := make([]byte, 1048576)
	testSignG1(message, t)
}

func TestSignG1RandomMessage(t *testing.T) {
	message := make([]byte, 65537)
	readRand(message, t)
	testSignG1(message, t)
}

func TestSignG1BadMessage(t *testing.T) {
	message := make([]byte, 1024)
	sk := genSecretKey(t)
	sig := genSignatureVt(sk, message, t)
	pk := genPublicKeyVt(sk, t)
	message = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	bls := NewSigPopVt()

	if res, _ := bls.Verify(pk, message, sig); res {
		t.Errorf("Expected signature to not verify")
	}
}

func TestBadConversionsG1(t *testing.T) {
	sk := genSecretKey(t)
	message := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	sig := genSignatureVt(sk, message, t)
	pk := genPublicKeyVt(sk, t)

	bls := NewSigPopVt()

	if res, _ := bls.Verify(pk, message, sig); !res {
		t.Errorf("Signature should be valid")
	}
	if res, _ := sig.verify(pk, message, blsSignaturePopVtDst); !res {
		t.Errorf("Signature should be valid")
	}

	// Convert public key to signature in G2
	sig2 := new(Signature)
	err := sig2.UnmarshalBinary(marshalStruct(pk, t))
	if err != nil {
		t.Errorf("Should be able to convert to signature in G2")
	}
	pk2 := new(PublicKey)
	err = pk2.UnmarshalBinary(marshalStruct(sig, t))
	if err != nil {
		t.Errorf("Should be able to convert to public key in G1")
	}

	res, _ := pk2.verifySignature(message, sig2, blsSignaturePopVtDst)
	if res {
		t.Errorf("The signature shouldn't verify")
	}
}

func TestAggregatePublicKeysG2(t *testing.T) {
	pks := []*PublicKeyVt{}
	ikm := make([]byte, 32)
	for i := 0; i < 20; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		pk := genPublicKeyVt(sk, t)
		pks = append(pks, pk)
	}
	apk1, err := aggregatePublicKeysVt(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	rand.Seed(1234567890)
	rand.Shuffle(len(pks), func(i, j int) { pks[i], pks[j] = pks[j], pks[i] })
	apk2, err := aggregatePublicKeysVt(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(apk1, t), marshalStruct(apk2, t)) {
		t.Errorf("Aggregated public keys should be equal")
	}
	rand.Shuffle(len(pks), func(i, j int) { pks[i], pks[j] = pks[j], pks[i] })
	apk1, err = aggregatePublicKeysVt(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(apk1, t), marshalStruct(apk2, t)) {
		t.Errorf("Aggregated public keys should be equal")
	}
}

func TestAggregateSignaturesG1(t *testing.T) {
	sigs := []*SignatureVt{}
	ikm := make([]byte, 32)
	for i := 0; i < 20; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		sig := genSignatureVt(sk, ikm, t)
		sigs = append(sigs, sig)
	}
	asig1, err := aggregateSignaturesVt(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	rand.Seed(1234567890)
	rand.Shuffle(len(sigs), func(i, j int) { sigs[i], sigs[j] = sigs[j], sigs[i] })
	asig2, err := aggregateSignaturesVt(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(asig1, t), marshalStruct(asig2, t)) {
		t.Errorf("Aggregated signatures should be equal")
	}
	rand.Shuffle(len(sigs), func(i, j int) { sigs[i], sigs[j] = sigs[j], sigs[i] })
	asig1, err = aggregateSignaturesVt(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(marshalStruct(asig1, t), marshalStruct(asig2, t)) {
		t.Errorf("Aggregated signatures should be equal")
	}
}

func initAggregatedTestValuesG1(messages [][]byte, t *testing.T) ([]*PublicKeyVt, []*SignatureVt) {
	pks := []*PublicKeyVt{}
	sigs := []*SignatureVt{}
	ikm := make([]byte, 32)
	for i := 0; i < numAggregateG1; i++ {
		readRand(ikm, t)
		sk := genRandSecretKey(ikm, t)
		sig := genSignatureVt(sk, messages[i%len(messages)], t)
		sigs = append(sigs, sig)
		pk := genPublicKeyVt(sk, t)
		pks = append(pks, pk)
	}
	return pks, sigs
}

func TestAggregatedFunctionalityG1(t *testing.T) {
	message := make([]byte, 20)
	messages := make([][]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG1(messages, t)

	bls := NewSigPopVt()
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
	if res, _ := asig.verify(apk, message, blsSignaturePopVtDst); !res {
		t.Errorf("MultiSignature.verify failed.")
	}
	if res, _ := apk.verify(message, asig, blsSignaturePopVtDst); !res {
		t.Errorf("MultiPublicKey.verify failed.")
	}
}

func TestBadAggregatedFunctionalityG1(t *testing.T) {
	message := make([]byte, 20)
	messages := make([][]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG1(messages, t)

	bls := NewSigPopVt()

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

func TestAggregateVerifyG1Pass(t *testing.T) {
	messages := make([][]byte, numAggregateG1)
	for i := 0; i < numAggregateG1; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); !res {
		t.Errorf("Expected aggregateVerify to pass but failed")
	}
}

func TestAggregateVerifyG1MsgSigCntMismatch(t *testing.T) {
	messages := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}

	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); res {
		t.Errorf("Expected AggregateVerifyG1 to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG1FailDupMsg(t *testing.T) {
	messages := make([][]byte, 10)
	for i := 0; i < 9; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	// Duplicate message
	messages[9] = messages[0]
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	if res, _ := bls.AggregateVerify(pks, messages, sigs); res {
		t.Errorf("Expected aggregateVerify to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG1FailIncorrectMsg(t *testing.T) {
	messages := make([][]byte, 10)
	for i := 0; i < 9; i++ {
		message := make([]byte, 20)
		readRand(message, t)
		messages[i] = message
	}
	// Duplicate message
	messages[9] = messages[0]
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	if res, _ := bls.AggregateVerify(pks[2:], messages[2:], sigs); res {
		t.Errorf("Expected aggregateVerify to fail with duplicate message but passed")
	}
}

func TestAggregateVerifyG1OneMsg(t *testing.T) {
	messages := make([][]byte, 1)
	messages[0] = make([]byte, 20)
	sk := genSecretKey(t)
	sig := genSignatureVt(sk, messages[0], t)
	pk := genPublicKeyVt(sk, t)
	bls := NewSigPopVt()
	// Should be the same as verifySignatureVt
	if res, _ := bls.AggregateVerify([]*PublicKeyVt{pk}, messages, []*SignatureVt{sig}); !res {
		t.Errorf("Expected AggregateVerifyG1OneMsg to pass but failed")
	}
}

func TestVerifyG1Mutability(t *testing.T) {
	//verify should not change any inputs
	ikm := make([]byte, 32)
	ikm_copy := make([]byte, 32)
	readRand(ikm, t)
	copy(ikm_copy, ikm)
	bls := NewSigPopVt()
	pk, sk, err := bls.KeygenWithSeed(ikm)

	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPopVt.KeygenWithSeed modifies ikm")
	}
	if err != nil {
		t.Errorf("Expected KeygenWithSeed to succeed but failed.")
	}
	sig, err := bls.Sign(sk, ikm)
	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPopVt.Sign modifies message")
	}
	if err != nil {
		t.Errorf("SigPopVt.KeygenWithSeed to succeed but failed.")
	}
	sigCopy := marshalStruct(sig, t)
	if res, _ := bls.Verify(pk, ikm, sig); !res {
		t.Errorf("Expected verify to succeed but failed.")
	}
	if !bytes.Equal(ikm, ikm_copy) {
		t.Errorf("SigPopVt.verify modifies message")
	}
	if !bytes.Equal(sigCopy, marshalStruct(sig, t)) {
		t.Errorf("SigPopVt.verify modifies signature")
	}
}

func TestPublicKeyG2FromBadBytes(t *testing.T) {
	pk := make([]byte, 32)
	err := new(PublicKeyVt).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG2FromBytes to fail but passed")
	}
	// All zeros
	pk = make([]byte, PublicKeyVtSize)
	// See https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
	// 1 << 7 == compressed
	// 1 << 6 == infinity or zero
	pk[0] = 0xc0
	err = new(PublicKeyVt).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG2FromBytes to fail but passed")
	}
	sk := genSecretKey(t)
	pk1, err := sk.GetPublicKeyVt()
	if err != nil {
		t.Errorf("Expected GetPublicKeyVt to pass but failed.")
	}
	out := marshalStruct(pk1, t)
	out[3] ^= out[4]
	err = new(PublicKeyVt).UnmarshalBinary(pk)
	if err == nil {
		t.Errorf("Expected PublicKeyG2FromBytes to fail but passed")
	}
}

func TestSignatureG1FromBadBytes(t *testing.T) {
	sig := make([]byte, 32)
	err := new(SignatureVt).UnmarshalBinary(sig)
	if err == nil {
		t.Errorf("Expected SignatureG1FromBytes to fail but passed")
	}
	// All zeros
	sig = make([]byte, SignatureVtSize)
	// See https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
	// 1 << 7 == compressed
	// 1 << 6 == infinity or zero
	sig[0] = 0xc0
	err = new(SignatureVt).UnmarshalBinary(sig)
	if err == nil {
		t.Errorf("Expected SignatureG1FromBytes to fail but passed")
	}
}

func TestBadSecretKeyG1(t *testing.T) {
	x := new(big.Int)
	sk := &SecretKey{value: *x}
	pk, err := sk.GetPublicKeyVt()
	if err == nil {
		t.Errorf("Expected GetPublicKeyVt to fail with 0 byte secret key but passed: %v", pk)
	}
	bls := bls12381.NewG2()
	_ = sk.UnmarshalBinary(bls.Q().Bytes())
	pk, err = sk.GetPublicKeyVt()
	if err == nil {
		t.Errorf("Expected GetPublicKeyVt to fail with secret key with Q but passed: %v", pk)
	}

	err = sk.UnmarshalBinary([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if err == nil {
		t.Errorf("Expected SecretKeyFromBytes to fail with not enough bytes but passed: %v", pk)
	}

	err = sk.UnmarshalBinary(make([]byte, 32))
	if err == nil {
		t.Errorf("Expected SecretKeyFromBytes to fail but passed: %v", pk)
	}
}

func TestProofOfPossessionG1Works(t *testing.T) {
	ikm := make([]byte, 32)
	readRand(ikm, t)
	bls := NewSigPopVt()
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

func TestProofOfPossessionG1FromBadKey(t *testing.T) {
	ikm := make([]byte, 32)
	value := new(big.Int)
	value.SetBytes(ikm)
	sk := SecretKey{value: *value}
	_, err := sk.createProofOfPossessionVt(blsSignaturePopVtDst)
	if err == nil {
		t.Errorf("createProofOfPossessionVt should've failed but succeeded.")
	}
}

func TestProofOfPossessionG1BytesWorks(t *testing.T) {
	sk := genSecretKey(t)
	pop, err := sk.createProofOfPossessionVt(blsSignaturePopVtDst)
	if err != nil {
		t.Errorf("CreateProofOfPossesionG1 failed but shouldn've succeeded.")
	}
	out := marshalStruct(pop, t)
	if len(out) != ProofOfPossessionVtSize {
		t.Errorf("ProofOfPossessionBytes incorrect size: expected %v, got %v", ProofOfPossessionVtSize, len(out))
	}
	pop2 := new(ProofOfPossessionVt)
	err = pop2.UnmarshalBinary(out)
	if err != nil {
		t.Errorf("ProofOfPossessionVt.UnmarshalBinary failed: %v", err)
	}
	out2 := marshalStruct(pop2, t)
	if !bytes.Equal(out, out2) {
		t.Errorf("ProofOfPossessionVt.UnmarshalBinary failed, not equal when deserialized")
	}
}

func TestProofOfPossessionG1BadBytes(t *testing.T) {
	zeros := make([]byte, ProofOfPossessionVtSize)
	temp := new(ProofOfPossessionVt)
	err := temp.UnmarshalBinary(zeros)
	if err == nil {
		t.Errorf("ProofOfPossessionVt.UnmarshalBinary shouldn've failed but succeeded.")
	}
}

func TestProofOfPossessionG1Fails(t *testing.T) {
	sk := genSecretKey(t)
	pop, err := sk.createProofOfPossessionVt(blsSignaturePopVtDst)
	if err != nil {
		t.Errorf("Expected createProofOfPossessionVt to succeed but failed.")
	}

	ikm := make([]byte, 32)
	readRand(ikm, t)
	sk = genRandSecretKey(ikm, t)
	bad, err := sk.GetPublicKeyVt()
	if err != nil {
		t.Errorf("Expected PublicKeyG2FromBytes to succeed but failed: %v", err)
	}
	if res, _ := pop.verify(bad, blsSignaturePopVtDst); res {
		t.Errorf("Expected ProofOfPossession verify to fail but succeeded.")
	}
}

func TestMultiSigG1Bytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	_, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	msig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	msigBytes := marshalStruct(msig, t)
	if len(msigBytes) != SignatureVtSize {
		t.Errorf("Invalid multi-sig length. Expected %d bytes, found %d", SignatureVtSize, len(msigBytes))
	}
	msig2 := new(MultiSignatureVt)
	err = msig2.UnmarshalBinary(msigBytes)
	if err != nil {
		t.Errorf("MultiSignatureG1FromBytes failed with %v", err)
	}
	msigBytes2 := marshalStruct(msig2, t)

	if !bytes.Equal(msigBytes, msigBytes2) {
		t.Errorf("Bytes methods not equal.")
	}
}

func TestMultiSigG1BadBytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	_, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	msig, err := bls.AggregateSignatures(sigs...)
	if err != nil {
		t.Errorf("%v", err)
	}
	msigBytes := marshalStruct(msig, t)
	if len(msigBytes) != SignatureVtSize {
		t.Errorf("Invalid multi-sig length. Expected %d bytes, found %d", SignatureSize, len(msigBytes))
	}
	msigBytes[0] = 0
	temp := new(MultiSignatureVt)
	err = temp.UnmarshalBinary(msigBytes)
	if err == nil {
		t.Errorf("MultiSignatureG1FromBytes should've failed but succeeded")
	}
	msigBytes = make([]byte, SignatureVtSize)
	err = temp.UnmarshalBinary(msigBytes)
	if err == nil {
		t.Errorf("MultiSignatureG1FromBytes should've failed but succeeded")
	}
}

func TestMultiPubkeyG2Bytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	pks, _ := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	apk, err := bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	apkBytes := marshalStruct(apk, t)
	if len(apkBytes) != PublicKeyVtSize {
		t.Errorf("MultiPublicKeyVt has an incorrect size")
	}
	apk2 := new(MultiPublicKeyVt)
	err = apk2.UnmarshalBinary(apkBytes)
	if err != nil {
		t.Errorf("MultiPublicKeyVt.UnmarshalBinary failed with %v", err)
	}
	apk2Bytes := marshalStruct(apk2, t)
	if !bytes.Equal(apkBytes, apk2Bytes) {
		t.Errorf("Bytes methods not equal.")
	}
}

func TestMultiPubkeyG2BadBytes(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 20)
	messages[0] = message
	pks, _ := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	apk, err := bls.AggregatePublicKeys(pks...)
	if err != nil {
		t.Errorf("%v", err)
	}
	apkBytes := marshalStruct(apk, t)
	if len(apkBytes) != PublicKeyVtSize {
		t.Errorf("MultiPublicKeyVt has an incorrect size")
	}
	apkBytes[0] = 0
	temp := new(MultiPublicKeyVt)
	err = temp.UnmarshalBinary(apkBytes)
	if err == nil {
		t.Errorf("MultiPublicKeyVt.UnmarshalBinary should've failed but succeeded")
	}
	apkBytes = make([]byte, PublicKeyVtSize)
	err = temp.UnmarshalBinary(apkBytes)
	if err == nil {
		t.Errorf("MultiPublicKeyVt.UnmarshalBinary should've failed but succeeded")
	}
}

func TestFastAggregateVerifyConstituentG1Works(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()

	if res, _ := bls.FastAggregateVerifyConstituent(pks, message, sigs); !res {
		t.Errorf("FastAggregateVerify failed.")
	}
}

func TestFastAggregateVerifyG1Works(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	asig, _ := aggregateSignaturesVt(sigs...)
	bls := NewSigPopVt()

	if res, _ := bls.FastAggregateVerify(pks, message, asig); !res {
		t.Errorf("FastAggregateVerify failed.")
	}
}

func TestFastAggregateVerifyG1Fails(t *testing.T) {
	messages := make([][]byte, 1)
	message := make([]byte, 1)
	messages[0] = message
	pks, sigs := initAggregatedTestValuesG1(messages, t)
	bls := NewSigPopVt()
	message[0] = 1
	if res, _ := bls.FastAggregateVerifyConstituent(pks, message, sigs); res {
		t.Errorf("FastAggregateVerify verified when it should've failed.")
	}
}

func TestCustomPopDstG1Works(t *testing.T) {
	bls, _ := NewSigPopVtWithDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_TEST",
		"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_TEST")
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

	pks := make([]*PublicKeyVt, 10)
	sigs := make([]*SignatureVt, 10)
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

func TestBlsPopG1KeyGenWithSeed(t *testing.T) {
	ikm := []byte("Not enough bytes")
	bls := NewSigPopVt()
	_, _, err := bls.KeygenWithSeed(ikm)
	if err == nil {
		t.Errorf("Expected KeygenWithSeed to fail but succeeded")
	}
}

func TestBlsPopG1KeyGen(t *testing.T) {
	bls := NewSigPopVt()
	_, _, err := bls.Keygen()
	if err != nil {
		t.Errorf("Keygen failed: %v", err)
	}
}

func TestPopVtThresholdKeygenBadInputs(t *testing.T) {
	bls := NewSigPopVt()
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

func TestPopVtThresholdKeygen(t *testing.T) {
	bls := NewSigPopVt()
	_, sks, err := bls.ThresholdKeygen(3, 5)
	if err != nil {
		t.Errorf("ThresholdKeygen failed")
	}
	if len(sks) != 5 {
		t.Errorf("ThresholdKeygen did not produce enough shares")
	}
}

func TestPopPartialSignVt(t *testing.T) {
	ikm := make([]byte, 32)
	bls := NewSigPopVt()
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
func TestPopVtPartialMixupShares(t *testing.T) {
	total := uint(5)
	ikm := make([]byte, 32)
	bls := NewSigPopVt()
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
