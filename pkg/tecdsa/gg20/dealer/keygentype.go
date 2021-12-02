//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dealer

// KeyGenType encapsulates the different methods
// that tecdsa can generate keys. Currently
// TrustedDealer or Distributed Key Generation
type KeyGenType interface {
	IsTrustedDealer() bool
	GetProofParams(id uint32) *ProofParams
}

// TrustedDealerKeyGenType means the same proof parameters
// will be used by all participants
type TrustedDealerKeyGenType struct {
	ProofParams *ProofParams
}

// DistributedKeyGenType means each participant has their
// own proof params that were distributed to each other
// participant
type DistributedKeyGenType struct {
	ProofParams map[uint32]*ProofParams
}

// IsTrustedDealer return true if TrustedDealerKeyGenType
func (td TrustedDealerKeyGenType) IsTrustedDealer() bool {
	return true
}

// GetProofParams returns the proof params specified by the participant id
func (td TrustedDealerKeyGenType) GetProofParams(_ uint32) *ProofParams {
	return td.ProofParams
}

// IsTrustedDealer return true if TrustedDealerKeyGenType
func (dkg DistributedKeyGenType) IsTrustedDealer() bool {
	return false
}

// GetProofParams returns the proof params specified by the participant id
func (dkg DistributedKeyGenType) GetProofParams(id uint32) *ProofParams {
	return dkg.ProofParams[id]
}
