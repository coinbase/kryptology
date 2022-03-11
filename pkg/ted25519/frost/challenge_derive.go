//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"crypto/sha512"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

type ChallengeDerive interface {
	DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error)
}

type Ed25519ChallengeDeriver struct{}

func (ed Ed25519ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	h := sha512.New()
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)
	return new(curves.ScalarEd25519).SetBytesWide(h.Sum(nil))
}
