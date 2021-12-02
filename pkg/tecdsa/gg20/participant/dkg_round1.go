//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
)

// DkgRound1Bcast contains values to be broadcast to all players after the completion of DKG round 1
type DkgRound1Bcast struct {
	Identifier       uint32
	Ci               core.Commitment
	Pki              *paillier.PublicKey
	H1i, H2i, Ni     *big.Int
	Proof1i, Proof2i *proof.CdlProof
}

// DkgRound1 performs round 1 distributed key generation operation
// [spec] fig 5: DistKeyGenRound1
func (dp *DkgParticipant) DkgRound1(threshold, total uint32) (*DkgRound1Bcast, error) {
	if total < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}

	if dp == nil || dp.Curve == nil {
		return nil, internal.ErrNilArguments
	}

	if err := dp.verifyDkgRound(1); err != nil {
		return nil, err
	}

	// Step 1: choose ui from Z_q randomly
	ui, err := core.Rand(dp.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Step 2: Compute [vi0,...,vit], [xi1,...,xin] <- FeldmanShare(g, ui, t, q, [p1...pn])
	feldman, err := v1.NewFeldman(threshold, total, dp.Curve)
	if err != nil {
		return nil, err
	}

	// V is an array of FeldmanVerifiers, X is an array of ShamirShares
	V, X, err := feldman.Split(ui.Bytes())
	if err != nil {
		return nil, err
	}

	// Convert V (type []FeldmanVerifier) to a single byteV (type []byte)
	var byteV []byte
	for i := 0; i < len(V); i++ {
		byteV = append(byteV, V[i].Bytes()...)
	}

	// Step 3: [Ci, Di] = Commit([vi0...vit])
	Ci, Di, err := core.Commit(byteV)
	if err != nil {
		return nil, err
	}

	// Step 4: ski, pki := PaillierKeyGen(1^k) (generate a 2048-bit Paillier key pair
	pki, ski, err := paillier.NewKeys()
	if err != nil {
		return nil, err
	}

	// Step 5-6: Choose 1024-bit safe primes Pi, Qi, Pi=2pi+1, Qi=2qi+1 where Pi, Qi, pi, qi are primes
	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	var Pi, Qi *big.Int
	for Pi == Qi {
		for range []int{1, 2} {
			go func() {
				value, err := core.GenerateSafePrime(paillier.PaillierPrimeBits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, err
			}
		}

		Pi, Qi = <-values, <-values
	}

	// Step 7: Compute tildeNi = Pi*Qi
	tildeNi := new(big.Int).Mul(Pi, Qi)

	// Step 8-9: Sample f, alpha from Z_tildeNi*
	f, err := core.Rand(tildeNi)
	if err != nil {
		return nil, err
	}

	alpha, err := core.Rand(tildeNi)
	if err != nil {
		return nil, err
	}

	// Step 10: Compute beta = alpha^-1 mod pi*qi
	// Compute pi = (Pi-1)/2, qi = (Qi-1)/2
	pi := new(big.Int).Rsh(Pi, 1)
	qi := new(big.Int).Rsh(Qi, 1)

	// Compute pi*qi
	pq := new(big.Int).Mul(pi, qi)

	// Compute beta
	beta := new(big.Int).ModInverse(alpha, pq)

	// Step 11-12: h1i = f^2 mod tildeNi, h2i = h1i^alpha mod tildeNi
	h1i, err := core.Mul(f, f, tildeNi)
	if err != nil {
		return nil, err
	}
	h2i := new(big.Int).Exp(h1i, alpha, tildeNi)

	// Step 13-14:
	cdlParams1 := proof.CdlProofParams{
		Curve:   dp.Curve,
		Pi:      pi,
		Qi:      qi,
		H1:      h1i,
		H2:      h2i,
		ScalarX: alpha,
		N:       tildeNi,
	}

	cdlParams2 := proof.CdlProofParams{
		Curve:   dp.Curve,
		Pi:      pi,
		Qi:      qi,
		H1:      h2i,
		H2:      h1i,
		ScalarX: beta,
		N:       tildeNi,
	}

	// proof1 <- ProveCompositeDL(g, q, pi, qi, h1i, h2i, alpha, tildeNi)
	proof1, err := cdlParams1.Prove()
	if err != nil {
		return nil, err
	}

	// proof2 <- ProveCompositeDl(g, q, pi, qi, h2i, h1i, beta, tildeNi)
	proof2, err := cdlParams2.Prove()
	if err != nil {
		return nil, err
	}

	// Step 16:
	// Store Di, ski, pki, tildeNi, h1i, h2i, [vi0...vit], [xi1,...xin] locally
	dp.state.D = Di
	dp.state.Sk = ski
	dp.state.Pk = pki
	dp.state.N = tildeNi
	dp.state.H1 = h1i
	dp.state.H2 = h2i
	dp.state.V = V
	dp.state.X = X
	dp.state.Threshold = threshold
	dp.state.Limit = total

	// used in Round 2
	dp.Round = 2

	// Step 15: EchoBroadcast Ci, pki, tildeNi, h1i, h2i, proof1, proof2
	return &DkgRound1Bcast{
		dp.id, Ci, pki, h1i, h2i, tildeNi, proof1, proof2,
	}, nil
}
