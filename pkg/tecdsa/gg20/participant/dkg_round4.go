//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
)

// DkgResult is all the data generated from the DKG
type DkgResult struct {
	PublicShares    []*curves.EcPoint
	VerificationKey *curves.EcPoint
	SigningKeyShare *big.Int
	EncryptionKey   *paillier.SecretKey
	ParticipantData map[uint32]*DkgParticipantData
}

type DkgParticipantData struct {
	PublicKey   *paillier.PublicKey
	ProofParams *dealer.ProofParams
}

// DkgRound4 computes dkg round 4 as shown in
// [spec] fig. 5: DistKeyGenRound4
func (dp *DkgParticipant) DkgRound4(psfProof map[uint32]paillier.PsfProof) (*DkgResult, error) {
	if len(psfProof) == 0 {
		return nil, internal.ErrIncorrectCount
	}
	if dp.Round != 4 {
		return nil, internal.ErrInvalidRound
	}
	// Make sure all participants sent a proof
	for id := range dp.state.otherParticipantData {
		if id == dp.id {
			continue
		}
		if _, ok := psfProof[id]; !ok {
			return nil, fmt.Errorf("missing proof for participant %d", id)
		}
	}

	verifyPsfParams := paillier.PsfVerifyParams{
		Curve: dp.Curve,
		Y:     dp.state.Y,
	}
	// 1. for j = [1,...,n]
	for id, p := range psfProof {
		// 2. if i == j, continue
		if dp.id == id {
			continue
		}
		verifyPsfParams.PublicKey = dp.state.otherParticipantData[id].PublicKey
		verifyPsfParams.Pi = id
		// 3. if VerifyPSF(\pi_j, pk_j.N, y, g, q, pj) = false, abort
		if err := p.Verify(&verifyPsfParams); err != nil {
			return nil, err
		}
	}

	// Return paillier public keys and proof params
	// from all participants
	participantData := make(map[uint32]*DkgParticipantData)
	for id, data := range dp.state.otherParticipantData {
		participantData[id] = &DkgParticipantData{
			PublicKey:   data.PublicKey,
			ProofParams: data.ProofParams,
		}
	}

	// Return all necessary information to complete signing
	// the proof params, paillier public keys, and public commitments
	// from other participants, the secret signing key share, and
	// the public verification key
	return &DkgResult{
		VerificationKey: dp.state.Y,
		SigningKeyShare: dp.state.Xi,
		PublicShares:    dp.state.PublicShares,
		EncryptionKey:   dp.state.Sk,
		ParticipantData: participantData,
	}, nil
}
