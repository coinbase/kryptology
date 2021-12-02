//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"bytes"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

type Signature = []byte

func Aggregate(sigs []*PartialSignature, config *ShareConfiguration) (Signature, error) {
	if len(sigs) == 0 {
		return nil, fmt.Errorf("ted25519: sigs must be non-empty")
	}

	// Verify all nonce pubKeys are the same by checking they all match the first one.
	noncePubkey := sigs[0].R()
	for i := 1; i < len(sigs); i++ {
		if !bytes.Equal(sigs[i].R(), noncePubkey) {
			return nil, fmt.Errorf(
				"ted25519: unexpected nonce pubkey. got: %x expected: %x",
				sigs[i].R(),
				noncePubkey,
			)
		}
	}

	// Convert signatures to a Shamir share representation so we can recombine them
	sigShares := make([]*v1.ShamirShare, len(sigs))
	field := curves.NewField(curves.Ed25519Order())
	shamir, err := v1.NewShamir(config.T, config.N, field)
	if err != nil {
		return nil, err
	}

	for i, sig := range sigs {
		sigShares[i] = v1.NewShamirShare(
			uint32(sig.ShareIdentifier),
			reverseBytes(sig.S()),
			field,
		)
	}

	sigS, err := shamir.Combine(sigShares...)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, signatureLength)
	copy(sig[:32], noncePubkey)        // R is the same on all sigs
	copy(sig[32:], reverseBytes(sigS)) // be-to-le

	return sig, nil
}
