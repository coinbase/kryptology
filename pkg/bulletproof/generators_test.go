package bulletproof

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestGeneratorsHappyPath(t *testing.T) {
	curve := curves.ED25519()
	gs, err := getGeneratorPoints(10, []byte("test"), *curve)
	gsConcatenated := concatIPPGenerators(*gs)
	require.NoError(t, err)
	require.Len(t, gs.G, 10)
	require.Len(t, gs.H, 10)
	require.True(t, noDuplicates(gsConcatenated))
}

func TestGeneratorsUniquePerDomain(t *testing.T) {
	curve := curves.ED25519()
	gs1, err := getGeneratorPoints(10, []byte("test"), *curve)
	gs1Concatenated := concatIPPGenerators(*gs1)
	require.NoError(t, err)
	gs2, err := getGeneratorPoints(10, []byte("test2"), *curve)
	gs2Concatenated := concatIPPGenerators(*gs2)
	require.NoError(t, err)
	require.True(t, areDisjoint(gs1Concatenated, gs2Concatenated))
}

func noDuplicates(gs generators) bool {
	seen := map[[32]byte]bool{}
	for _, G := range gs {
		value := sha3.Sum256(G.ToAffineCompressed())
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func areDisjoint(gs1, gs2 generators) bool {
	for _, g1 := range gs1 {
		for _, g2 := range gs2 {
			if g1.Equal(g2) {
				return false
			}
		}
	}
	return true
}

func concatIPPGenerators(ippGens ippGenerators) generators {
	var out generators
	out = append(out, ippGens.G...)
	out = append(out, ippGens.H...)
	return out
}
