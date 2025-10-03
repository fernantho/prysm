package query_test

import (
	"testing"

	"github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
	sszquerypb "github.com/OffchainLabs/prysm/v6/proto/ssz_query"
	"github.com/OffchainLabs/prysm/v6/testing/require"
)

func TestHashTreeRoot_basic(t *testing.T) {
	fixedNestedContainer := &sszquerypb.FixedNestedContainer{
		Value1: 42,
		Value2: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	info, err := query.AnalyzeObject(fixedNestedContainer)
	require.NoError(t, err)
	require.NotNil(t, info, "Expected non-nil SSZ info")

	hashTreeRoot, err := info.HashTreeRoot()
	require.NoError(t, err, "HashTreeRoot should not return an error")
	t.Logf("HashTreeRoot: %x", hashTreeRoot)

	expectedHashTreeRoot, err := fixedNestedContainer.HashTreeRoot()
	require.NoError(t, err, "HashTreeRoot on original object should not return an error")
	require.Equal(t, expectedHashTreeRoot, hashTreeRoot, "HashTreeRoot from sszInfo should match original object's HashTreeRoot")
}
