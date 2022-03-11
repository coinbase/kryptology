package main

import (
	crand "crypto/rand"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
)

func main() {
	// Setup
	curve := curves.ED25519()
	serverPk, serverSk, _ := elgamal.NewKeys(curve)
	aliceEk, _, _ := elgamal.NewKeys(curve)
	bobEk, _, _ := elgamal.NewKeys(curve)

	signKey := curve.Scalar.Random(crand.Reader)
	verKey := curve.ScalarBaseMult(signKey)

	shamir, _ := sharing.NewShamir(2, 2, curve)
	shares, _ := shamir.Split(signKey, crand.Reader)

	// Create a proof s.t. Alice and Bob submit
	// proofs of correctness for their ciphertexts
	// Alice and Bob can decrypt their respective shares
	// But the server cannot.
	// The server checks whether the ciphertexts
	// are valid encrypted shares
	aliceDomain := []byte("alice_share")
	bobDomain := []byte("bob_share")
	aliceStuff := computeProof(curve, shares[0].Value, aliceDomain, aliceEk, serverPk)
	bobStuff := computeProof(curve, shares[1].Value, bobDomain, bobEk, serverPk)

	if !verifyProof(curve, aliceStuff, aliceDomain, aliceEk, serverPk) {
		panic("bad alice proof")
	}
	if !verifyProof(curve, bobStuff, bobDomain, bobEk, serverPk) {
		panic("bad bob proof")
	}
	aliceShare, _ := aliceStuff.serverctxt.ToHomomorphicCipherText().Decrypt(serverSk)
	bobShare, _ := bobStuff.serverctxt.ToHomomorphicCipherText().Decrypt(serverSk)

	avk := shamirCombinePoint(curve, []curves.Point{aliceShare, bobShare})
	if avk.Equal(verKey) {
		fmt.Println("Success")
	} else {
		fmt.Println("Failure")
	}
}

func shamirCombinePoint(curve *curves.Curve, points []curves.Point) curves.Point {
	result := curve.Point.Identity()

	for i, p := range points {
		basis := curve.Scalar.One()
		for j := range points {
			if i == j {
				continue
			}

			// x_m - x_j
			denom := curve.Scalar.New(j + 1).Sub(curve.Scalar.New(i + 1))
			if denom.IsZero() {
				return nil
			}
			// x_m / x_m - x_j
			basis = basis.Mul(curve.Scalar.New(j + 1).Div(denom))
		}

		result = result.Add(p.Mul(basis))
	}

	return result
}

func verifyProof(
	curve *curves.Curve,
	proof *commitTwinProof,
	domain []byte,
	encKey *elgamal.EncryptionKey,
	serverPk *elgamal.EncryptionKey,
) bool {
	genBytes := append(domain, encKey.Value.ToAffineUncompressed()...)
	genBytes = append(genBytes, proof.encctxt.Nonce...)
	h := curve.NewGeneratorPoint().Hash(genBytes)

	w1 := curve.ScalarBaseMult(proof.d).Add(serverPk.Value.Mul(proof.d1)).Add(proof.serverctxt.C2.Mul(proof.c))
	w2 := h.Mul(proof.d).Add(encKey.Value.Mul(proof.d2)).Add(proof.encctxt.C2.Mul(proof.c))
	c := curve.NewScalar().Hash(append(w1.ToAffineCompressed(), w2.ToAffineCompressed()...))
	return c.Cmp(proof.c) == 0
}

type commitTwinProof struct {
	c, d, d1, d2 curves.Scalar
	serverctxt   *elgamal.CipherText
	encctxt      *elgamal.CipherText
}

func computeProof(
	curve *curves.Curve,
	share, domain []byte,
	encKey *elgamal.EncryptionKey,
	servKey *elgamal.EncryptionKey,
) *commitTwinProof {
	r1 := curve.Scalar.Random(crand.Reader)
	r2 := curve.Scalar.Random(crand.Reader)
	encctxt, _, _ := encKey.VerifiableEncrypt(share, &elgamal.EncryptParams{
		Domain:          domain,
		Blinding:        r2,
		MessageIsHashed: true,
		ProofNonce:      domain,
	})
	serverCtxt, _, _ := servKey.VerifiableEncrypt(share, &elgamal.EncryptParams{
		Blinding:        r1,
		MessageIsHashed: true,
		ProofNonce:      domain,
	})

	w := curve.Scalar.Random(crand.Reader)
	n1 := curve.Scalar.Random(crand.Reader)
	n2 := curve.Scalar.Random(crand.Reader)

	genBytes := append(domain, encKey.Value.ToAffineUncompressed()...)
	genBytes = append(genBytes, encctxt.Nonce...)
	h := curve.NewGeneratorPoint().Hash(genBytes)

	w1 := curve.ScalarBaseMult(w).Add(servKey.Value.Mul(n1))
	w2 := h.Mul(w).Add(encKey.Value.Mul(n2))
	c := curve.NewScalar().Hash(append(w1.ToAffineCompressed(), w2.ToAffineCompressed()...))
	s, err := curve.NewScalar().SetBytes(share)
	if err != nil {
		panic(err)
	}
	// d = w - c s
	d := w.Sub(c.Mul(s))
	// d1 = n1 - c r1
	d1 := n1.Sub(c.Mul(r1))
	// d2 = n2 - c r2
	d2 := n2.Sub(c.Mul(r2))

	return &commitTwinProof{
		c:          c,
		d:          d,
		d1:         d1,
		d2:         d2,
		encctxt:    encctxt,
		serverctxt: serverCtxt,
	}
}
