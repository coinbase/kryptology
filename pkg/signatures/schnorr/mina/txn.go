//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/btcsuite/btcutil/base58"
)

// Transaction is a Mina transaction for payments or delegations
type Transaction struct {
	Fee, FeeToken        uint64
	FeePayerPk           *PublicKey
	Nonce, ValidUntil    uint32
	Memo                 string
	Tag                  [3]bool
	SourcePk, ReceiverPk *PublicKey
	TokenId, Amount      uint64
	Locked               bool
	NetworkId            NetworkType
}

type txnJson struct {
	Common txnCommonJson
	Body   [2]interface{}
}

type txnCommonJson struct {
	Fee        uint64 `json:"fee"`
	FeeToken   uint64 `json:"fee_token"`
	FeePayerPk string `json:"fee_payer_pk"`
	Nonce      uint32 `json:"nonce"`
	ValidUntil uint32 `json:"valid_until"`
	Memo       string `json:"memo"`
	NetworkId  uint8  `json:"network_id"`
}

type txnBodyPaymentJson struct {
	SourcePk   string `json:"source_pk"`
	ReceiverPk string `json:"receiver_pk"`
	TokenId    uint64 `json:"token_id"`
	Amount     uint64 `json:"amount"`
}

type txnBodyDelegationJson struct {
	Delegator   string `json:"delegator"`
	NewDelegate string `json:"new_delegate"`
}

func (txn *Transaction) MarshalBinary() ([]byte, error) {
	mapper := map[bool]byte{
		true:  1,
		false: 0,
	}
	out := make([]byte, 175)
	binary.LittleEndian.PutUint64(out, txn.Fee)
	binary.LittleEndian.PutUint64(out[8:16], txn.FeeToken)
	copy(out[16:48], txn.FeePayerPk.value.ToAffineCompressed())
	binary.LittleEndian.PutUint32(out[48:52], txn.Nonce)
	binary.LittleEndian.PutUint32(out[52:56], txn.ValidUntil)

	out[56] = 0x01
	out[57] = byte(len(txn.Memo))
	copy(out[58:90], txn.Memo[:])
	out[90] = mapper[txn.Tag[0]]
	out[91] = mapper[txn.Tag[1]]
	out[92] = mapper[txn.Tag[2]]
	copy(out[93:125], txn.SourcePk.value.ToAffineCompressed())
	copy(out[125:157], txn.ReceiverPk.value.ToAffineCompressed())
	binary.LittleEndian.PutUint64(out[157:165], txn.TokenId)
	binary.LittleEndian.PutUint64(out[165:173], txn.Amount)
	out[173] = mapper[txn.Locked]
	out[174] = byte(txn.NetworkId)
	return out, nil
}

func (txn *Transaction) UnmarshalBinary(input []byte) error {
	mapper := map[byte]bool{
		1: true,
		0: false,
	}
	if len(input) < 175 {
		return fmt.Errorf("invalid byte sequence")
	}
	feePayerPk := new(PublicKey)
	sourcePk := new(PublicKey)
	receiverPk := new(PublicKey)
	err := feePayerPk.UnmarshalBinary(input[16:48])
	if err != nil {
		return err
	}
	err = sourcePk.UnmarshalBinary(input[93:125])
	if err != nil {
		return err
	}
	err = receiverPk.UnmarshalBinary(input[125:157])
	if err != nil {
		return err
	}
	txn.Fee = binary.LittleEndian.Uint64(input[:8])
	txn.FeeToken = binary.LittleEndian.Uint64(input[8:16])
	txn.FeePayerPk = feePayerPk
	txn.Nonce = binary.LittleEndian.Uint32(input[48:52])
	txn.ValidUntil = binary.LittleEndian.Uint32(input[52:56])
	txn.Memo = string(input[58 : 58+input[57]])
	txn.Tag[0] = mapper[input[90]]
	txn.Tag[1] = mapper[input[91]]
	txn.Tag[2] = mapper[input[92]]
	txn.SourcePk = sourcePk
	txn.ReceiverPk = receiverPk
	txn.TokenId = binary.LittleEndian.Uint64(input[157:165])
	txn.Amount = binary.LittleEndian.Uint64(input[165:173])
	txn.Locked = mapper[input[173]]
	txn.NetworkId = NetworkType(input[174])
	return nil
}

func (txn *Transaction) UnmarshalJSON(input []byte) error {
	var t txnJson
	err := json.Unmarshal(input, &t)
	if err != nil {
		return err
	}
	strType, ok := t.Body[0].(string)
	if !ok {
		return fmt.Errorf("unexpected type")
	}
	memo, _, err := base58.CheckDecode(t.Common.Memo)
	if err != nil {
		return err
	}
	if strType == "Payment" {
		b, ok := t.Body[1].(txnBodyPaymentJson)
		if !ok {
			return fmt.Errorf("unexpected type")
		}
		feePayerPk := new(PublicKey)
		err = feePayerPk.ParseAddress(b.SourcePk)
		if err != nil {
			return err
		}
		receiverPk := new(PublicKey)
		err = receiverPk.ParseAddress(b.ReceiverPk)
		if err != nil {
			return nil
		}
		txn.FeePayerPk = feePayerPk
		txn.ReceiverPk = receiverPk
	} else if strType == "Stake_delegation" {
		bType, ok := t.Body[1].([2]interface{})
		if !ok {
			return fmt.Errorf("unexpected type")
		}
		delegateType, ok := bType[0].(string)
		if !ok {
			return fmt.Errorf("unexpected type")
		}
		if delegateType == "Set_delegate" {
			b, ok := bType[1].(txnBodyDelegationJson)
			if !ok {
				return fmt.Errorf("unexpected type")
			}
			feePayerPk := new(PublicKey)
			err = feePayerPk.ParseAddress(b.Delegator)
			if err != nil {
				return err
			}
			receiverPk := new(PublicKey)
			err = receiverPk.ParseAddress(b.NewDelegate)
			if err != nil {
				return err
			}
			txn.FeePayerPk = feePayerPk
			txn.ReceiverPk = receiverPk
		} else {
			return fmt.Errorf("unexpected type")
		}
	} else {
		return fmt.Errorf("unexpected type")
	}
	txn.Memo = string(memo[2 : 2+memo[1]])
	sourcePk := new(PublicKey)
	sourcePk.value = new(curves.Ep).Set(txn.FeePayerPk.value)
	txn.Fee = t.Common.Fee
	txn.FeeToken = t.Common.FeeToken
	txn.Nonce = t.Common.Nonce
	txn.ValidUntil = t.Common.ValidUntil
	txn.NetworkId = NetworkType(t.Common.NetworkId)
	return nil
}

func (txn Transaction) addRoInput(input *roinput) {
	input.AddFp(txn.FeePayerPk.value.X())
	input.AddFp(txn.SourcePk.value.X())
	input.AddFp(txn.ReceiverPk.value.X())

	input.AddUint64(txn.Fee)
	input.AddUint64(txn.FeeToken)
	input.AddBit(txn.FeePayerPk.value.Y().IsOdd())
	input.AddUint32(txn.Nonce)
	input.AddUint32(txn.ValidUntil)
	memo := [34]byte{0x01, byte(len(txn.Memo))}
	copy(memo[2:], txn.Memo)
	input.AddBytes(memo[:])
	for _, b := range txn.Tag {
		input.AddBit(b)
	}

	input.AddBit(txn.SourcePk.value.Y().IsOdd())
	input.AddBit(txn.ReceiverPk.value.Y().IsOdd())
	input.AddUint64(txn.TokenId)
	input.AddUint64(txn.Amount)
	input.AddBit(txn.Locked)
}
