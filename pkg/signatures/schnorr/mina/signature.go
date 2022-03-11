//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

// Signature is a Mina compatible signature either for payment or delegation
type Signature struct {
	R *fp.Fp
	S *fq.Fq
}

func (sig Signature) MarshalBinary() ([]byte, error) {
	var buf [64]byte
	rx := sig.R.Bytes()
	s := sig.S.Bytes()
	copy(buf[:32], rx[:])
	copy(buf[32:], s[:])
	return buf[:], nil
}

func (sig *Signature) UnmarshalBinary(input []byte) error {
	if len(input) != 64 {
		return fmt.Errorf("invalid byte sequence")
	}
	var buf [32]byte
	copy(buf[:], input[:32])
	rx, err := new(fp.Fp).SetBytes(&buf)
	if err != nil {
		return err
	}
	copy(buf[:], input[32:])
	s, err := new(fq.Fq).SetBytes(&buf)
	if err != nil {
		return err
	}
	sig.R = rx
	sig.S = s
	return nil
}
