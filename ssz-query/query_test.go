package sszquery_test

import (
	"testing"

	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	sszquery "github.com/OffchainLabs/prysm/v6/ssz-query"
	"github.com/OffchainLabs/prysm/v6/testing/assert"
)

func TestPreCalculateSSZInfo(t *testing.T) {
	// Test with a valid object.
	obj := &ethpb.IndexedAttestationElectra{}
	info, err := sszquery.PreCalculateSSZInfo(obj)
	if err != nil {
		t.Fatalf("PreCalculateSSZInfo failed: %v", err)
	}

	assert.NotNil(t, info, "Expected non-nil SSZ info")
	assert.Equal(t, uint64(228), info.FixedSize(), "Expected fixed size to be 228")
}

func TestCalculateOffset(t *testing.T) {
	// Target path: .data.target.root
	path, err := sszquery.ParsePath(".data.target.root")
	if err != nil {
		t.Fatalf("ParsePath failed: %v", err)
	}

	info, err := sszquery.PreCalculateSSZInfo(&ethpb.IndexedAttestationElectra{})
	if err != nil {
		t.Fatalf("PreCalculateSSZInfo failed: %v", err)
	}

	offset, err := sszquery.CalculateOffset(info, path)
	if err != nil {
		t.Fatalf("ResolvePath failed: %v", err)
	}

	assert.Equal(t, uint64(100), offset, "Expected offset to be 100")
}
