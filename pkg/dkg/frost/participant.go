//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package frost is an implementation of the DKG part of  https://eprint.iacr.org/2020/852.pdf
package frost

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"strconv"

	"github.com/coinbase/kryptology/internal"
)

type DkgParticipant struct {
	round                  int
	Curve                  *curves.Curve
	otherParticipantShares map[uint32]*dkgParticipantData
	Id                     uint32
	SkShare                curves.Scalar
	VerificationKey        curves.Point
	VkShare                curves.Point
	feldman                *sharing.Feldman
	verifiers              *sharing.FeldmanVerifier
	secretShares           []*sharing.ShamirShare
	ctx                    byte
}

type dkgParticipantData struct {
	Id        uint32
	Share     *sharing.ShamirShare
	Verifiers *sharing.FeldmanVerifier
}

func NewDkgParticipant(id, threshold uint32, ctx string, curve *curves.Curve, otherParticipants ...uint32) (*DkgParticipant, error) {
	if curve == nil || len(otherParticipants) == 0 {
		return nil, internal.ErrNilArguments
	}
	limit := uint32(len(otherParticipants)) + 1
	feldman, err := sharing.NewFeldman(threshold, limit, curve)
	if err != nil {
		return nil, err
	}
	otherParticipantShares := make(map[uint32]*dkgParticipantData, len(otherParticipants))
	for _, id := range otherParticipants {
		otherParticipantShares[id] = &dkgParticipantData{
			Id: id,
		}
	}

	// SetBigInt the common fixed string
	ctxV, _ := strconv.Atoi(ctx)

	return &DkgParticipant{
		Id:                     id,
		round:                  1,
		Curve:                  curve,
		feldman:                feldman,
		otherParticipantShares: otherParticipantShares,
		ctx:                    byte(ctxV),
	}, nil
}
