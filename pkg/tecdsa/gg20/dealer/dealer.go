//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dealer

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// ParticipantData represents all data to be sent to a participant
// after the dealer is finished
type ParticipantData struct {
	Id             uint32
	DecryptKey     *paillier.SecretKey
	SecretKeyShare *Share
	// Public values set to all signing participants
	EcdsaPublicKey *curves.EcPoint
	KeyGenType     KeyGenType
	PublicShares   map[uint32]*PublicShare
	EncryptKeys    map[uint32]*paillier.PublicKey
}

type ParticipantDataJson struct {
	Id             uint32
	DecryptKey     *paillier.SecretKey
	SecretKeyShare *Share
	// Public values set to all signing participants
	EcdsaPublicKey    *curves.EcPoint
	DealerParams      *ProofParams
	ParticipantParams map[uint32]*ProofParams
	PublicShares      map[uint32]*PublicShare
	EncryptKeys       map[uint32]*paillier.PublicKey
}

func (pd ParticipantData) MarshalJSON() ([]byte, error) {
	data := ParticipantDataJson{
		Id:             pd.Id,
		DecryptKey:     pd.DecryptKey,
		SecretKeyShare: pd.SecretKeyShare,
		EcdsaPublicKey: pd.EcdsaPublicKey,
		PublicShares:   pd.PublicShares,
		EncryptKeys:    pd.EncryptKeys,
	}
	if pd.KeyGenType.IsTrustedDealer() {
		data.DealerParams = pd.KeyGenType.GetProofParams(0)
	} else {
		data.ParticipantParams = pd.KeyGenType.(DistributedKeyGenType).ProofParams
	}
	return json.Marshal(data)
}

func (pd *ParticipantData) UnmarshalJSON(bytes []byte) error {
	data := new(ParticipantDataJson)
	if err := json.Unmarshal(bytes, data); err != nil {
		return err
	}
	if data.DealerParams != nil {
		pd.KeyGenType = TrustedDealerKeyGenType{
			ProofParams: data.DealerParams,
		}
	} else {
		pd.KeyGenType = DistributedKeyGenType{
			ProofParams: data.ParticipantParams,
		}
	}
	pd.Id = data.Id
	pd.EncryptKeys = data.EncryptKeys
	pd.DecryptKey = data.DecryptKey
	pd.SecretKeyShare = data.SecretKeyShare
	pd.PublicShares = data.PublicShares
	pd.EcdsaPublicKey = data.EcdsaPublicKey
	return nil
}

// ProofParams is the modulus and generators
// used when constructing keys and completing the signing rounds
type ProofParams struct {
	// n is the modulus for the signing rounds, product of two safe primes
	N *big.Int
	// h1 random value quadratic residue in n
	H1 *big.Int
	// h2 is a random modular power of h1
	H2 *big.Int
}

// PublicShare can be sent to a Participant so it can be used to convert Share to its additive form
type PublicShare struct {
	Point *curves.EcPoint
}

// Share represents a piece of the ECDSA private key and a commitment to the share
type Share struct {
	*v1.ShamirShare
	Point *curves.EcPoint
}

// ShareJson encapsulates the data that is serialized to JSON
// used internally and not for external use. Public so other pieces
// can use for serialization
type ShareJson struct {
	Identifier uint32   // x-coordinate
	Value      *big.Int // y-coordinate
	Point      *curves.EcPoint
}

func (s Share) MarshalJSON() ([]byte, error) {
	return json.Marshal(ShareJson{
		Identifier: s.Identifier,
		Value:      s.Value.BigInt(),
		Point:      s.Point,
	})
}

func (s *Share) UnmarshalJSON(bytes []byte) error {
	sh := ShareJson{}
	err := json.Unmarshal(bytes, &sh)
	if err != nil {
		return err
	}
	s.ShamirShare = new(v1.ShamirShare)
	s.ShamirShare.Identifier = sh.Identifier
	f := curves.NewField(sh.Point.Curve.Params().N)
	s.ShamirShare.Value = f.NewElement(sh.Value)
	s.Point = sh.Point
	return nil
}

// NewProofParams creates new ProofParams with `bits` sized values
func NewProofParams() (*ProofParams, error) {
	return genProofParams(core.GenerateSafePrime, core.Rand, paillier.PaillierPrimeBits)
}

// NewProofParamsWithPrimes creates new ProofParams using the
// parameters as the primes
func NewProofParamsWithPrimes(p, q *big.Int) (*ProofParams, error) {
	pIdx := 0
	safePrimes := []*big.Int{p, q}
	f := func(bits uint) (*big.Int, error) {
		r := safePrimes[pIdx]
		pIdx = (pIdx + 1) % 2
		return r, nil
	}
	return genProofParams(f, core.Rand, paillier.PaillierPrimeBits)
}

// PreparePublicShares makes public shares that can be sent
// to the participant to compute their additive shares and participate in signing rounds
func PreparePublicShares(sharesMap map[uint32]*Share) (map[uint32]*PublicShare, error) {
	if len(sharesMap) == 0 {
		return nil, fmt.Errorf("sharesMap cannot be nil or empty")
	}
	publicSharesMap := make(map[uint32]*PublicShare, len(sharesMap))
	for i, p := range sharesMap {
		if p == nil {
			return nil, fmt.Errorf("share cannot be nil")
		}
		publicSharesMap[i] = &PublicShare{p.Point}
	}
	return publicSharesMap, nil
}

// New Secret generates a new private key
func NewSecret(curve elliptic.Curve) (*big.Int, error) {
	return core.Rand(curve.Params().N)
}

func DerivePublicKey(curve elliptic.Curve, secretKey *big.Int) (*curves.EcPoint, error) {
	return curves.NewScalarBaseMult(curve, secretKey)
}

// NewDealerShares generates the Secp256k1 private key shares and public key
// if ikm == nil, a new private key will be generated
func NewDealerShares(curve elliptic.Curve, threshold, total uint32, ikm *big.Int) (*curves.EcPoint, map[uint32]*Share, error) {
	if total < threshold {
		return nil, nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if total > 255 {
		return nil, nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if curve.Params().BitSize != 256 {
		return nil, nil, fmt.Errorf("invalid curve size")
	}
	var err error
	if ikm == nil {
		ikm, err = NewSecret(curve)
		if err != nil {
			return nil, nil, err
		}
	}

	pk, err := DerivePublicKey(curve, ikm)
	if err != nil {
		return nil, nil, err
	}

	q := curves.NewField(curve.Params().N)
	shamir, err := v1.NewShamir(int(threshold), int(total), q)
	if err != nil {
		return nil, nil, err
	}
	// Create the shares to be distributed to participants
	shares, err := shamir.Split(ikm.Bytes())
	if err != nil {
		return nil, nil, err
	}

	dSharesMap := make(map[uint32]*Share, total)
	for i, s := range shares {
		// Create a commitment to the private share value
		publicShare, err := curves.NewScalarBaseMult(curve, s.Value.BigInt())
		if err != nil {
			return nil, nil, err
		}
		dSharesMap[uint32(i+1)] = &Share{
			s,
			publicShare,
		}
	}
	return pk, dSharesMap, nil
}

// genProofParams creates all the values needed for ProofParams using the specified
// genSafePrime function, genRandInMod function, and number of bits
func genProofParams(genSafePrime func(uint) (*big.Int, error), genRandInMod func(*big.Int) (*big.Int, error), bits uint) (*ProofParams, error) {

	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	var p, q *big.Int

	for p == q {
		for range []int{1, 2} {
			go func() {
				value, err := genSafePrime(bits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, err
			}
		}

		p, q = <-values, <-values
	}

	// Compute modulus
	n := new(big.Int).Mul(p, q)

	var f, alpha *big.Int

	for f == alpha {
		for range []int{1, 2} {
			go func() {
				value, err := genRandInMod(n)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, err
			}
		}

		f, alpha = <-values, <-values
	}

	// Compute Quadratic Residue generator h1
	h1, err := core.Mul(f, f, n)
	if err != nil {
		return nil, err
	}
	// Compute a modular exponent of h1 as h2
	h2 := new(big.Int).Exp(h1, alpha, n)
	return &ProofParams{n, h1, h2}, nil
}
