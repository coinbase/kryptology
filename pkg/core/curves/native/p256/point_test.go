package p256_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/p256"
	"github.com/coinbase/kryptology/pkg/core/curves/native/p256/fp"
)

func TestP256PointArithmetic_Double(t *testing.T) {
	g := p256.P256PointNew().Generator()
	pt1 := p256.P256PointNew().Double(g)
	pt2 := p256.P256PointNew().Add(g, g)
	pt3 := p256.P256PointNew().Mul(g, fp.P256FpNew().SetUint64(2))

	e1 := pt1.Equal(pt2)
	e2 := pt1.Equal(pt3)
	e3 := pt2.Equal(pt3)
	require.Equal(t, 1, e1)
	require.Equal(t, 1, e2)
	require.Equal(t, 1, e3)
}

func TestP256PointArithmetic_Hash(t *testing.T) {
	var b [32]byte
	sc, err := p256.P256PointNew().Hash(b[:], native.EllipticPointHasherSha256())
	sc1 := curves.P256().NewIdentityPoint().Hash(b[:])
	fmt.Printf("%v\n", sc1)

	require.NoError(t, err)
	require.True(t, !sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
