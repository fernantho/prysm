package sszquery_test

import (
	"testing"

	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	sszquery "github.com/OffchainLabs/prysm/v6/ssz-query"
	"github.com/OffchainLabs/prysm/v6/testing/assert"
)

func TestCalculateOffset(t *testing.T) {
	// Build indexed attestation struct for testing.
	data := &ethpb.AttestationData{
		BeaconBlockRoot: params.BeaconConfig().ZeroHash[:],
		Source: &ethpb.Checkpoint{
			Epoch: primitives.Epoch(42),
			Root:  []byte{'a'},
		},
		Target: &ethpb.Checkpoint{
			Epoch: primitives.Epoch(43),
			Root:  []byte{'b'},
		},
	}

	indexedAtt := &ethpb.IndexedAttestationElectra{
		AttestingIndices: []uint64{1, 2, 3},
		Data:             data,
		Signature:        []byte{'c'},
	}

	// Target path: .data.target.root
	path := ".data.target.root"

	offset, err := sszquery.CalculateOffset(indexedAtt, path)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	assert.Equal(t, uint64(100), offset, "Expected offset to be 100")
}
