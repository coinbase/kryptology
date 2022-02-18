//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package gennaro is an implementation of the DKG part of https://eprint.iacr.org/2020/540.pdf
package gennaro

import (
	"crypto/elliptic"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"

	"github.com/coinbase/kryptology/internal"
)

// Participant is a DKG player that contains information needed to perform DKG rounds
// and yield a secret key share and public key when finished
type Participant struct {
	round                  int
	curve                  elliptic.Curve
	scalar                 curves.EcScalar
	otherParticipantShares map[uint32]*dkgParticipantData
	id                     uint32
	skShare                *curves.Element
	verificationKey        *v1.ShareVerifier
	feldman                *v1.Feldman
	pedersen               *v1.Pedersen
	pedersenResult         *v1.PedersenResult
}

// NewParticipant creates a participant ready to perform a DKG
// `id` is the integer value identifier for this participant
// `threshold` is the minimum bound for the secret sharing scheme
// `generator` is the blinding factor generator used by pedersen's verifiable secret sharing
// `otherParticipants` is the integer value identifiers for the other participants
// `id` and `otherParticipants` must be the set of integers 1,2,....,n
func NewParticipant(id, threshold uint32, generator *curves.EcPoint, scalar curves.EcScalar, otherParticipants ...uint32) (*Participant, error) {
	if generator == nil || len(otherParticipants) == 0 {
		return nil, internal.ErrNilArguments
	}
	err := validIds(append(otherParticipants, id))
	if err != nil {
		return nil, err
	}

	limit := uint32(len(otherParticipants)) + 1
	feldman, err := v1.NewFeldman(threshold, limit, generator.Curve)
	if err != nil {
		return nil, err
	}
	pedersen, err := v1.NewPedersen(threshold, limit, generator)
	if err != nil {
		return nil, err
	}

	otherParticipantShares := make(map[uint32]*dkgParticipantData, len(otherParticipants))
	for _, id := range otherParticipants {
		otherParticipantShares[id] = &dkgParticipantData{
			Id: id,
		}
	}

	return &Participant{
		id:                     id,
		round:                  1,
		curve:                  generator.Curve,
		scalar:                 scalar,
		feldman:                feldman,
		pedersen:               pedersen,
		otherParticipantShares: otherParticipantShares,
	}, nil
}

// Determines if the SSIDs are exactly the values 1..n.
func validIds(ids []uint32) error {
	// Index
	idMap := make(map[uint32]bool, len(ids))
	for _, id := range ids {
		idMap[id] = true
	}
	// Check
	for i := 1; i <= len(ids); i++ {
		if ok := idMap[uint32(i)]; !ok {
			return fmt.Errorf("the ID list %v is invalid. Values must be 1,2,..,n.", ids)
		}
	}
	return nil
}

type dkgParticipantData struct {
	Id        uint32
	Share     *v1.ShamirShare
	Verifiers []*v1.ShareVerifier
}
