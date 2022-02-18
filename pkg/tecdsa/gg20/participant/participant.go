//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package participant is an implementation of a `participant` in the t-of-n threshold signature of https://eprint.iacr.org/2020/540.pdf
package participant

import (
	"crypto/elliptic"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"math/big"
	"reflect"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// Participant is a tECDSA player that receives information from a trusted dealer
type Participant struct {
	dealer.Share
	sk *paillier.SecretKey
}

// Signer is a tECDSA player that holds the additive shares needed for performing the signing operation
type Signer struct {
	sk              *paillier.SecretKey            // paillier secret key assigned to this signer
	share           *v1.ShamirShare                // secret signing share for this signer
	publicSharesMap map[uint32]*dealer.PublicShare // public shares of our cosigners
	id              uint32                         // The ID assigned to this signer's shamir share
	// This is minimum number of signers required to produce a valid signature,
	// not the security threshold (as specified in [spec][GG20])
	threshold uint
	PublicKey *curves.EcPoint
	Curve     elliptic.Curve
	Round     uint   // current signing round in our linear state machine
	state     *state // Accumulated intermediate values associated with signing
}

// NewSigner C=creates a new signer from a dealer-provided output and a specific set of co-signers
func NewSigner(info *dealer.ParticipantData, cosigners []uint32) (*Signer, error) {
	// Create the participant
	p := Participant{*info.SecretKeyShare, info.DecryptKey}

	// Skinny down the sharesMap to just the chosen ones
	chosenOnes := make(map[uint32]*dealer.PublicShare, len(cosigners))
	for _, id := range cosigners {
		chosenOnes[id] = info.PublicShares[id]
	}

	// Convert to additive shares and return the resultx
	return p.PrepareToSign(
		info.EcdsaPublicKey,
		func(*curves.EcPoint, []byte, *curves.EcdsaSignature) bool {
			return true
		},
		info.EcdsaPublicKey.Curve,
		info.KeyGenType,
		chosenOnes,
		info.EncryptKeys)
}

// verifyStateMap verifies the round is the expected round number and
// that the set of signers from in.keys() exactly matches the set
// in state.cosigners.
func (signer *Signer) verifyStateMap(round uint, in interface{}) error {
	// Check the expected round against internal state
	if signer.Round != round {
		return internal.ErrInvalidRound
	}

	// If no map was provided, we're done.
	if in == nil {
		return nil
	}

	// Otherwise, verify that the map contains exactly our current
	// set of cosigners (except for our own ID)
	v := reflect.ValueOf(in)
	if v.Kind() != reflect.Map {
		return fmt.Errorf("parameter `in` must be a map; instead is %v", v.Kind())
	}
	// Put these keys into a map for fast lookup
	inCosignersMap := make(map[uint32]bool, len(v.MapKeys()))
	for _, id := range v.MapKeys() {
		inCosignersMap[uint32(id.Uint())] = true
	}

	// Check for superfluous cosigners in the input
	for id := range inCosignersMap {
		if id != signer.id && !signer.state.cosigners[id] {
			return fmt.Errorf("cosigner id=%v is not valid", id)
		}
	}

	// Check for missing cosigners in the input
	for id := range signer.state.cosigners {
		if id != signer.id && !inCosignersMap[id] {
			return fmt.Errorf("missing input from cosigner id=%v", id)
		}
	}

	// Success!
	return nil
}

// setCosigners establishes the list of cosigner IDs. This may or may not include self ID.
func (signer *Signer) setCosigners(in []uint32) error {
	// Ensure the input is exactly the right length
	if len(in) != int(signer.threshold-1) && len(in) != int(signer.threshold) {
		return internal.ErrIncorrectCount
	}

	// Save off this list of signers
	signer.state.cosigners = make(map[uint32]bool, len(in))
	for _, id := range in {
		signer.state.cosigners[id] = true
	}
	return nil
}

// resetSignRound sets the signer to a pre-round1 state.
func (signer *Signer) resetSignRound() {
	signer.Round = 1
	signer.state = nil
}

// state encapsulates all the values used in the signing rounds state machine
type state struct {
	keyGenType dealer.KeyGenType
	verify     curves.EcdsaVerify
	msgHash    []byte

	// List of IDs of the other participants that we expect to see in each round
	cosigners map[uint32]bool

	// Round 1 variables
	ki     *big.Int
	gammai *big.Int
	Gammai *curves.EcPoint
	Ci     core.Commitment
	Di     *core.Witness
	ci     paillier.Ciphertext
	ri     *big.Int

	// Round 2 variables
	cj    map[uint32]paillier.Ciphertext
	Cj    map[uint32]core.Commitment
	betaj map[uint32]*big.Int
	vuj   map[uint32]*big.Int
	pks   map[uint32]*paillier.PublicKey

	// Round 3 variables
	deltai *big.Int
	sigmai *big.Int

	// Round 4 variables
	delta *big.Int

	// Round 5 variables
	r     *big.Int
	Rbari *curves.EcPoint
	Rbark *curves.EcPoint
	R     *curves.EcPoint

	// Round 6 variables
	si *big.Int
}

// convertToAdditive takes all the publicShares and changes them to their additive form
// for this participant. Only t shares are needed for this step
// [spec] §4.figure 4: convertToAdditive
func (p Participant) convertToAdditive(curve elliptic.Curve, publicSharesMap map[uint32]*dealer.PublicShare) (*Signer, error) {
	if publicSharesMap == nil {
		return nil, fmt.Errorf("public shares cannot be nil")
	}
	if len(publicSharesMap) < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	emptyP := Participant{Share: dealer.Share{}}
	if p == emptyP || p.Value == nil || p.Point == nil {
		return nil, fmt.Errorf("participant share cannot be nil")
	}

	field := curves.NewField(curve.Params().N)
	x, err := makeXMap(curve, publicSharesMap)
	if err != nil {
		return nil, err
	}

	additiveMap := make(map[uint32]*dealer.PublicShare, len(publicSharesMap))
	var maxIndex uint32 = 0
	var privateKeyShare *v1.ShamirShare

	// Compute lagrange coefficients
	for j := range publicSharesMap {
		// l is our lambda_j
		l := field.One()
		for k := range publicSharesMap {
			// Don't compute lagrange coefficients for self-point
			if j == k {
				continue
			}

			// lambda(j) = \Prod_{j \= k} { x_k / (x_k - x_j) }
			den := x[k].Sub(x[j])
			if den.IsEqual(field.Zero()) {
				return nil, fmt.Errorf("unable to calculate additive shares due to duplicates")
			}
			l = l.Mul(x[k].Div(den))
		}

		// Additive public shares for all signers this round
		w, err := publicSharesMap[j].Point.ScalarMult(l.BigInt())
		if err != nil {
			return nil, err
		}

		additiveMap[j] = &dealer.PublicShare{Point: w}
		if j > maxIndex {
			maxIndex = j
		}

		// compute additive private share
		if j == p.Identifier {
			wI := l.Mul(field.ElementFromBytes(p.Share.Value.Bytes()))
			privateKeyShare = v1.NewShamirShare(p.Share.Identifier, wI.Bytes(), field)
		}
	}

	return &Signer{
		sk:              p.sk,
		share:           privateKeyShare,
		publicSharesMap: additiveMap,
		Round:           1,
		state:           &state{},
	}, nil
}

// PrepareToSign creates a Signer out of a Participant. The expected co-signers for the signing rounds are
// expected to be exactly those included in the publicSharesMap
func (p Participant) PrepareToSign(pubKey *curves.EcPoint,
	verify curves.EcdsaVerify,
	curve elliptic.Curve,
	keyGenType dealer.KeyGenType,
	publicSharesMap map[uint32]*dealer.PublicShare,
	pubKeys map[uint32]*paillier.PublicKey) (*Signer, error) {
	if pubKey == nil || verify == nil || curve == nil || keyGenType == nil || len(publicSharesMap) < 1 {
		return nil, internal.ErrNilArguments
	}
	signer, err := p.convertToAdditive(curve, publicSharesMap)
	if err != nil {
		return nil, err
	}
	signer.id = signer.share.Identifier

	signer.state.cosigners = make(map[uint32]bool, len(publicSharesMap)-1)
	for id := range publicSharesMap {
		if id == p.Identifier {
			continue
		}
		if _, ok := pubKeys[id]; !ok {
			return nil, fmt.Errorf("missing public key for signer %v", id)
		}
		signer.state.cosigners[id] = true
	}
	// Store co-signer pubkeys for round 2 and 6
	signer.PublicKey = pubKey
	signer.Curve = curve
	signer.state.pks = pubKeys
	signer.state.keyGenType = keyGenType
	signer.state.verify = verify
	signer.threshold = uint(len(publicSharesMap))
	return signer, nil
}

// Creates a map of polynomial x-coordinates that are field elements.
func makeXMap(curve elliptic.Curve, publicSharesMap map[uint32]*dealer.PublicShare) (map[uint32]*curves.Element, error) {
	field := curves.NewField(curve.Params().N)
	x := make(map[uint32]*curves.Element, len(publicSharesMap))

	// Convert identifiers to a field element
	for i, ps := range publicSharesMap {
		if ps == nil {
			return nil, internal.ErrNilArguments
		}

		x[i] = field.ElementFromBytes([]byte{byte(i)})
	}
	return x, nil
}

// DkgParticipant is a DKG player that contains information needed to perform DKG rounds and finally get info for signing rounds.
type DkgParticipant struct {
	Curve elliptic.Curve
	state *dkgstate
	id    uint32
	Round uint
}

type dkgParticipantData struct {
	PublicKey   *paillier.PublicKey
	ProofParams *dealer.ProofParams
	Commitment  core.Commitment
}

// dkgstate encapsulates all the values used in the dkg rounds state machine
type dkgstate struct {
	// Round 1 variables
	D  *core.Witness
	Sk *paillier.SecretKey
	Pk *paillier.PublicKey
	N  *big.Int
	H1 *big.Int
	H2 *big.Int
	// This participants verifiers from FeldmanShare
	V []*v1.ShareVerifier
	// This participants shares from FeldmanShare
	X         []*v1.ShamirShare
	Y         *curves.EcPoint
	Threshold uint32
	Limit     uint32
	// Commitments and paillier public keys received from other participants
	otherParticipantData map[uint32]*dkgParticipantData
	// xi returned from Round 3
	Xi *big.Int
	// X1,...,Xn returned from Round 3
	PublicShares []*curves.EcPoint
}

// Check DKG round number is valid
func (dp *DkgParticipant) verifyDkgRound(dkground uint) error {
	if dp.Round != dkground {
		return internal.ErrInvalidRound
	}
	return nil
}
