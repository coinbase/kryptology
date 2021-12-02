//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/elliptic"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// DkgRound3 computes dkg round 3 as shown in
// [spec] fig. 5: DistKeyGenRoun3
func (dp *DkgParticipant) DkgRound3(d map[uint32]*core.Witness, x map[uint32]*v1.ShamirShare) (paillier.PsfProof, error) {
	if len(d) == 0 || len(x) == 0 {
		return nil, internal.ErrNilArguments
	}
	if dp.Round != 3 {
		return nil, internal.ErrInvalidRound
	}

	// Extract the share verifiers from the commitment
	verifiers := make(map[uint32][]*v1.ShareVerifier, len(d))
	// NOTE: ID-1 because participant IDs are 1-based
	verifiers[dp.id] = dp.state.V
	verifierSize := internal.CalcFieldSize(dp.Curve) * 2
	feldman, err := v1.NewFeldman(dp.state.Threshold, dp.state.Limit, dp.Curve)
	if err != nil {
		return nil, err
	}

	// 1. set xi = xii
	xi := dp.state.X[dp.id-1]

	// 2. for j = [1,...,n]
	for j, wit := range d {
		// 3. if i == j continue
		if j == dp.id {
			continue
		}
		// 4. Compute [vj0, . . . , vjt] ←Open(Cj , Dj )
		if ok, err := core.Open(dp.state.otherParticipantData[j].Commitment, *d[j]); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid witness for participant %d", j+1)
			}
		}

		verifiers[j], err = unmarshalFeldmanVerifiers(dp.Curve, wit.Msg, verifierSize, int(dp.state.Threshold))
		if err != nil {
			return nil, err
		}

		// 6. If FeldmanVerify(g, q, xji, pi, [vj0, . . . , vjt]) = False, Abort
		if ok, err := feldman.Verify(x[j], verifiers[j]); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant %d", j+1)
			}
		}

		// 7. Compute xi = xi + xji mod q
		xi.Value = xi.Value.Add(x[j].Value)
	}

	v := make([]*curves.EcPoint, dp.state.Threshold)
	// 8. for j = [0,...,t]
	for j := 0; j < int(dp.state.Threshold); j++ {
		// 9. Set vj = 1 or identity point
		v[j], err = curves.NewScalarBaseMult(dp.Curve, big.NewInt(0))
		if err != nil {
			return nil, err
		}

		// 10. for k = [1,...,n]
		for _, verifier := range verifiers {
			// 11. Compute vj = vj · vkj in G
			v[j], err = v[j].Add(verifier[j])
			if err != nil {
				return nil, err
			}
		}
	}

	// 12. y = v0 i.e the public key
	y := v[0]

	// This is a sanity check to make sure nothing went wrong when
	// computing the public key
	if !dp.Curve.IsOnCurve(y.X, y.Y) || y.IsIdentity() {
		return nil, fmt.Errorf("invalid public key")
	}

	// Xj's
	publicShares := make([]*curves.EcPoint, dp.state.Limit)

	// 13. for j = [1,...,n]
	for j := 0; j < int(dp.state.Limit); j++ {
		id := uint32(j + 1)
		// 14. Set Xj = y
		publicShares[j] = &curves.EcPoint{
			Curve: dp.Curve,
			X:     new(big.Int).Set(y.X),
			Y:     new(big.Int).Set(y.Y),
		}
		// 15. for k = [1,...,t]
		for k := 0; k < int(dp.state.Threshold); k++ {
			// 16. compute ck = pj^k mod q
			pj := big.NewInt(int64(id))
			ck, err := core.Mul(pj, big.NewInt(int64(k+1)), dp.Curve.Params().N)
			if err != nil {
				return nil, err
			}
			// 17. compute Xj = Xj x vk ^ ck in G
			t, err := v[k].ScalarMult(ck)
			if err != nil {
				return nil, err
			}
			// Xj = Xj * t in G
			publicShares[j], err = publicShares[j].Add(t)
			if err != nil {
				return nil, err
			}
		}
	}

	// 18. Compute πPSF = ProvePSF(ski.N, ski.φ(N), y, g, q, pi)
	psfParams := paillier.PsfProofParams{
		Curve:     dp.Curve,
		SecretKey: dp.state.Sk,
		Pi:        dp.id,
		Y:         y,
	}
	psfProof, err := psfParams.Prove()
	if err != nil {
		return nil, err
	}

	dp.Round = 4
	dp.state.Y = y
	dp.state.Xi = xi.Value.BigInt()
	dp.state.PublicShares = publicShares

	return psfProof, nil
}

// unmarshalFeldmanVerifiers converts a byte sequence into
// a number of feldman verifiers
func unmarshalFeldmanVerifiers(curve elliptic.Curve, msg []byte, verifierSize, threshold int) ([]*v1.ShareVerifier, error) {
	if len(msg)%verifierSize != 0 {
		return nil, fmt.Errorf("invalid committed verifier shares")
	}
	numShares := len(msg) / verifierSize

	// 5. If [vj0,...,vjt] = ⊥, Abort
	if numShares != threshold {
		return nil, fmt.Errorf("invalid number of verifier shares")
	}

	// Extract verifiers from bytes
	verifiers := make([]*v1.ShareVerifier, numShares)
	var err error
	for k := 0; k < numShares; k++ {
		value := make([]byte, verifierSize)
		copy(value, msg[k*verifierSize:(k+1)*verifierSize])
		verifiers[k], err = curves.PointFromBytesUncompressed(curve, value)
		if err != nil {
			return nil, err
		}
	}
	return verifiers, nil
}
