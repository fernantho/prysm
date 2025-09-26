package query

import (
	"testing"

	sszquerypb "github.com/OffchainLabs/prysm/v6/proto/ssz_query"
	"github.com/OffchainLabs/prysm/v6/testing/require"
)

func TestEmptyBitlist(t *testing.T) {
	emptyBitlist := []byte{} // Represents an empty bitlist with only the delimiter bit set
	bitlistContainer := &sszquerypb.BitlistContainer{
		BitlistField: emptyBitlist,
	}

	info, err := AnalyzeObject(bitlistContainer)
	if err != nil {
		t.Fatalf("AnalyzeObject failed: %v", err)
	}

	// Get the container info to access individual fields
	containerInfo, err := info.ContainerInfo()
	if err != nil {
		t.Fatalf("ContainerInfo failed: %v", err)
	}

	// Access the BitlistField specifically
	fields := containerInfo.fields
	bitlistFieldInfo, exists := fields["bitlist_field"]
	if !exists {
		t.Fatalf("BitlistField not found in container fields")
	}

	// Get the SSZ info for the bitlist field
	bitlistSSZInfo := bitlistFieldInfo.sszInfo
	require.NotNil(t, bitlistSSZInfo, "Expected non-nil SSZ info for BitlistField")

	// Get bitlist-specific info
	bitlistInfo, err := bitlistSSZInfo.BitlistInfo()
	if err != nil {
		t.Fatalf("BitlistInfo failed: %v", err)
	}

	require.NotNil(t, bitlistInfo, "Expected non-nil BitlistInfo")
	require.Equal(t, uint64(2048), bitlistInfo.Limit(), "Expected limit to be 2048 (from ssz_max annotation)")
	require.Equal(t, uint64(0), bitlistInfo.Length(), "Expected length to be 0 for empty bitlist")
	require.Equal(t, uint64(0), bitlistInfo.Size(), "Expected size to be 0 byte for empty bitlist with delimiter")
}
