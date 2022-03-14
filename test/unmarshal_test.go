package test

import (
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUnmarshaling(t *testing.T) {
	blsScheme := bls_sig.NewSigEth2()
	_, sks, err := blsScheme.ThresholdKeygen(3, 5)
	require.NoError(t, err)

	for _, sk := range sks {
		b1, err := sk.MarshalBinary()
		require.NoError(t, err)

		// UnmarshalBinary giving empty sk.value
		sk1 := new(bls_sig.SecretKeyShare)
		err = sk1.UnmarshalBinary(b1)
		require.NoError(t, err)

		// minus 1 because of identifier
		zeros := make([]byte, len(b1)-1)
		b2, err := sk1.MarshalBinary()
		require.Equal(t, zeros, b2[1:])
	}
}
