//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package common

import (
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// ProofMessage classifies how a message is presented in a proof
// Either Revealed or Hidden. Hidden has two sub categories:
// proof specific i.e. the message is only used for this proof or
// shared i.e. the message should be proved to be common across proofs
type ProofMessage interface {
	// IsHidden indicates the message should be hidden
	IsHidden() bool
	// GetBlinding is used for hidden messages
	// blindings can either be proof specific to a signature
	// or involved with other proofs like boundchecks,
	// set memberships, or inequalities so the blinding
	// factor is shared among proofs to produce a common
	// schnorr linking proof
	GetBlinding(reader io.Reader) curves.Scalar
	// GetMessage returns the underlying message
	GetMessage() curves.Scalar
}

type RevealedMessage struct {
	Message curves.Scalar
}

func (r RevealedMessage) IsHidden() bool {
	return false
}

func (r RevealedMessage) GetBlinding(reader io.Reader) curves.Scalar {
	return nil
}

func (r RevealedMessage) GetMessage() curves.Scalar {
	return r.Message
}

type ProofSpecificMessage struct {
	Message curves.Scalar
}

func (ps ProofSpecificMessage) IsHidden() bool {
	return true
}

func (ps ProofSpecificMessage) GetBlinding(reader io.Reader) curves.Scalar {
	return ps.Message.Random(reader)
}

func (ps ProofSpecificMessage) GetMessage() curves.Scalar {
	return ps.Message
}

type SharedBlindingMessage struct {
	Message, Blinding curves.Scalar
}

func (ps SharedBlindingMessage) IsHidden() bool {
	return true
}

func (ps SharedBlindingMessage) GetBlinding(reader io.Reader) curves.Scalar {
	return ps.Blinding
}

func (ps SharedBlindingMessage) GetMessage() curves.Scalar {
	return ps.Message
}
