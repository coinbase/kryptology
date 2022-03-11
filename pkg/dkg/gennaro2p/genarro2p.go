//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package gennaro2p wraps dkg/genarro and specializes it for the 2-party case. Simpler API, no
// distinction between broadcast and peer messages, and only counterparty messages are
// used as round inputs since self-inputs are always ignored.
package gennaro2p

import (
	"crypto/elliptic"
	"fmt"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/gennaro"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

const threshold = 2

// Participant is a DKG player that contains information needed to perform DKG rounds
// and yield a secret key share and public key when finished
type Participant struct {
	id             uint32
	counterPartyId uint32
	embedded       *gennaro.Participant
	blind          *curves.EcPoint
}

type Round1Message struct {
	Verifiers     []*v1.ShareVerifier
	SecretShare   *v1.ShamirShare
	BlindingShare *v1.ShamirShare
	Blind         *curves.EcPoint
}

type Round2Message struct {
	Verifiers []*v1.ShareVerifier
}

type DkgResult struct {
	PublicKey    *curves.EcPoint
	SecretShare  *v1.ShamirShare
	PublicShares map[uint32]*curves.EcPoint
}

// NewParticipant creates a participant ready to perform a DKG
// blind must be a generator and must be synchronized between counterparties.
// The first participant can set it to `nil` and a secure blinding factor will be
// generated.
func NewParticipant(id, counterPartyId uint32, blind *curves.EcPoint,
	scalar curves.EcScalar, curve elliptic.Curve) (*Participant, error) {
	// Generate blinding value, if required
	var err error
	if blind == nil {
		blind, err = newBlind(scalar, curve)
		if err != nil {
			return nil, errors.Wrap(err, "generating fresh blinding generator")
		}
	}
	p, err := gennaro.NewParticipant(id, threshold, blind, scalar, counterPartyId)
	if err != nil {
		return nil, errors.Wrap(err, "created genarro.Participant")
	}
	return &Participant{id, counterPartyId, p, blind}, nil
}

// Creates a random blinding factor (as a generator) required for pedersen's VSS
func newBlind(curveScalar curves.EcScalar, curve elliptic.Curve) (*curves.EcPoint, error) {
	rScalar, err := curveScalar.Random()
	if err != nil {
		return nil, errors.Wrap(err, "generating blinding scalar")
	}
	return curves.NewScalarBaseMult(curve, rScalar)
}

// Runs DKG round 1. If `secret` is nil, shares of a new, random signing key are generated.
// Otherwise, the existing secret shares will be refreshed but the privkey and pubkey
// will remain unchanged.
func (p *Participant) Round1(secret []byte) (*Round1Message, error) {
	// Run round 1
	bcast, p2p, err := p.embedded.Round1(secret)
	if err != nil {
		return nil, errors.Wrap(err, "calling embedded.Round1()")
	}

	// Ensure the map has the expected entry so there's no SIGSEGV when we
	// repackage it
	if p2p[p.counterPartyId] == nil {
		return nil, fmt.Errorf("round1 response for p2p[%v] is nil", p.counterPartyId)
	}

	// Package response
	return &Round1Message{
		bcast,
		p2p[p.counterPartyId].SecretShare,
		p2p[p.counterPartyId].BlindingShare,
		p.blind,
	}, nil
}

// Runs DKG round 2 using the counterparty's output from round 1.
func (p *Participant) Round2(msg *Round1Message) (*Round2Message, error) {
	// Run round 2
	bcast, err := p.embedded.Round2(
		map[uint32]gennaro.Round1Bcast{
			p.counterPartyId: msg.Verifiers,
		},
		map[uint32]*gennaro.Round1P2PSendPacket{
			p.counterPartyId: {
				SecretShare:   msg.SecretShare,
				BlindingShare: msg.BlindingShare,
			}})
	if err != nil {
		return nil, errors.Wrap(err, "calling embedded.Round2()")
	}

	// Package response
	return &Round2Message{bcast}, nil
}

// Completes the DKG using the counterparty's output from round 2.
func (p *Participant) Finalize(msg *Round2Message) (*DkgResult, error) {
	// Run round 3
	pk, share, err := p.embedded.Round3(
		map[uint32]gennaro.Round2Bcast{
			p.counterPartyId: msg.Verifiers,
		})
	if err != nil {
		return nil, errors.Wrap(err, "calling embedded.Round3()")
	}

	// Compute public shares
	pubShares, err := p.embedded.Round4()
	if err != nil {
		return nil, errors.Wrap(err, "calling embedded.Roun4()")
	}

	// Package response
	return &DkgResult{
		PublicKey:    pk,
		SecretShare:  share,
		PublicShares: pubShares,
	}, nil
}
