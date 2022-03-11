//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
)

// Round6FullBcast are the values to be broadcast to the other players
// This is the s_i value from §5.fig 5.SignRound6.step 9
type (
	Round6FullBcast struct {
		// Note that sElement is some element of the entire s vector.
		// In this round, it's s_i. For the recepients of this message in the final
		// sign output round, this will be s_j
		sElement *big.Int
		// The reason we can't do something straightforward like `type BetterRound6FullBcast *big.int`
		// is that although `big.int` has some methods implementing marshaler,
		// they won't be accessible to `BetterRound6FullBcast`. So the json.Marhsal uses the default methods
		// and since the two fields of `big.int` are not exported, the data of `BetterRound6FullBcast`
		// won't actually be serialized and its deserialization results in nil.
	}

	Round6FullBcastJSON struct {
		SElement *big.Int
	}
)

func (r6b Round6FullBcast) MarshalJSON() ([]byte, error) {
	return json.Marshal(Round6FullBcastJSON{r6b.sElement})
}

func (r6b *Round6FullBcast) UnmarshalJSON(data []byte) error {
	message := &Round6FullBcastJSON{}
	err := json.Unmarshal(data, message)
	if err != nil {
		return err
	}
	r6b.sElement = message.SElement
	return nil
}

// SignRound6Full performs the round 6 signing operation according to
// Trusted Dealer Mode: see [spec] fig 7: SignRound6
// DKG Mode: see [spec] fig 8: SignRound6
func (signer *Signer) SignRound6Full(hash []byte, in map[uint32]*Round5Bcast, p2p map[uint32]*Round5P2PSend) (*Round6FullBcast, error) {
	if err := signer.verifyStateMap(6, in); err != nil {
		return nil, err
	}

	if !signer.state.keyGenType.IsTrustedDealer() {
		if err := signer.verifyStateMap(6, p2p); err != nil {
			return nil, err
		}
	}

	// Steps 1-6
	err := signer.signRound6Offline(in, p2p)
	if err != nil {
		return nil, err
	}

	// Steps 7-10
	return signer.signRound6Online(hash)
}

// signRound6Offline performs the round 6 signing operation according to
// [spec] §6.fig 6
// Verifies the accumulated computed values before signing the final result
func (signer *Signer) signRound6Offline(in map[uint32]*Round5Bcast, p2p map[uint32]*Round5P2PSend) error {
	// FUTURE: determine round state variables to accommodate on/offline modes
	// before this function is exported
	var err error

	// 1. Set V = \bar{R}_i
	v := signer.state.Rbari

	// 2. For j=[1,...,t+1]
	for j, value := range in {
		// 3. If i = j, Continue
		if j == signer.id {
			continue
		}

		// 4. TrustedDealer - If VerifyPDL(πkCONSIST,g,q,R,pkj,N,h1,h2,cj,Rj) = False, Abort
		// 4. DKG - If VerifyPDL(πkCONSIST_j,g,q,R,pkj,Nj,h1j,h2j,cj,Rj) = False, Abort
		// Pseudocode says i when it should be j
		verifyProofParams := &proof.PdlVerifyParams{
			Curve:        signer.Curve,
			Pk:           signer.state.pks[j],
			DealerParams: signer.state.keyGenType.GetProofParams(signer.id),
			PointX:       value.Rbar,
			PointR:       signer.state.R,
			C:            signer.state.cj[j],
		}
		if signer.state.keyGenType.IsTrustedDealer() {
			if err := value.Proof.Verify(verifyProofParams); err != nil {
				return err
			}
		} else {
			if err := p2p[j].Verify(verifyProofParams); err != nil {
				return err
			}
		}

		// 5. Compute V = V · R_j in G
		v, err = v.Add(value.Rbar)
		if err != nil {
			return err
		}
	}
	// 6 If V != g, Abort
	if !v.IsBasePoint() {
		return fmt.Errorf("V != g")
	}
	// 7. return r, k, \sigma,
	// These are already stored
	return nil
}

// SignRound6Online performs the round 6 signing operation according to
// [spec] §6.fig 6.SignRound6Online
// func (p Participant) SignRound6Online(msg []byte, k, r, sigma *big.Int, curve elliptic.Curve) (*Round6FullBcast, *Round6FullOut, error) {
func (signer *Signer) signRound6Online(hash []byte) (*Round6FullBcast, error) {
	// FUTURE: check the current round state if allowed to be called separately

	// 7. Compute m = H(M) ∈ Z_q
	// We receive the message already hashed to allow flexibility for the callers
	// to hash the message according to the library they use
	// However, we check the hash is in the field
	m := new(big.Int).SetBytes(hash)
	if err := core.In(m, signer.Curve.Params().N); err != nil {
		return nil, err
	}
	signer.state.msgHash = hash

	// 8. Compute s_i = m k_i + r σ_i mod q
	m, err := core.Mul(m, signer.state.ki, signer.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	rTmp, err := core.Mul(signer.state.r, signer.state.sigmai, signer.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	si, err := core.Add(m, rTmp, signer.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	signer.state.si = si
	signer.Round = 7

	// 9. Broadcast s_i to all other players
	// 10. Return s_i
	return &Round6FullBcast{si}, nil
}

// SignOutput performs the signature aggregation step in
// [spec] §5.fig 5
func (signer *Signer) SignOutput(in map[uint32]*Round6FullBcast) (*curves.EcdsaSignature, error) {
	var err error
	if err = signer.verifyStateMap(7, in); err != nil {
		return nil, err
	}
	// 1. Set s = s_i
	s := new(big.Int).Set(signer.state.si)

	// 2. For j = [1,...,t+1]
	for j, sj := range in {
		// 3. If i = j, continue
		if j == signer.id {
			continue
		}

		// 4. Compute s = s + s_j mod q
		s, err = core.Add(s, sj.sElement, signer.Curve.Params().N)
		if err != nil {
			return nil, err
		}
	}

	sOld := new(big.Int).Set(s)
	s = signer.normalizeS(s)
	v := int(signer.state.R.Y.Bit(0))

	if sOld.Cmp(s) != 0 {
		v ^= 1
	}

	// 5. Set \sigma = (r, s)
	sigma := &curves.EcdsaSignature{V: v, R: signer.state.r, S: s}

	// 6. If ECDSAVerify(y, \sigma, M) = False, Abort
	if !signer.state.verify(signer.PublicKey, signer.state.msgHash, sigma) {
		return nil, fmt.Errorf("signature is not valid")
	}

	// 7. Return \sigma
	return sigma, nil
}

func (signer Signer) normalizeS(s *big.Int) *big.Int {
	// Normalize the signature to a "low S" form. In ECDSA, signatures are
	// of the form (r, s) where r and s are numbers lying in some finite
	// field. The verification equation will pass for (r, s) iff it passes
	// for (r, -s), so it is possible to ``modify'' signatures in transit
	// by flipping the sign of s. This does not constitute a forgery since
	// the signed message still cannot be changed, but for some applications,
	// changing even the signature itself can be a problem. Such applications
	// require a "strong signature". It is believed that ECDSA is a strong
	// signature except for this ambiguity in the sign of s, so to accommodate
	// these applications we will only produce signatures for which
	// s is in the lower half of the field range. This eliminates the
	// ambiguity.
	//
	// However, for some systems, signatures with high s-values are considered
	// valid. (For example, parsing the historic Bitcoin blockchain requires
	// this.) We normalize to the low S form which ensures that the s value
	// lies in the lower half of its range.
	// See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>
	qDiv2 := new(big.Int)
	qDiv2 = qDiv2.Div(signer.Curve.Params().N, core.Two)

	// Check whether a scalar is higher than the group order divided
	// by 2. If true, we negate s.
	// Not constant time, it would be better to conditionally negate with check in constant time
	// but since `s` is a public value anyway, this is allowed to be variable time
	if s.Cmp(qDiv2) == 1 {
		return new(big.Int).Sub(signer.Curve.Params().N, s)
	}
	return new(big.Int).Set(s)
}
