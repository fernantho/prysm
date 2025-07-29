package sszquery_test

import (
	"testing"

	sszquery "github.com/OffchainLabs/prysm/v6/ssz-query"
	"github.com/OffchainLabs/prysm/v6/testing/assert"
)

func TestParsePath(t *testing.T) {
	// Test parsing a simple path
	path := ".data.target.root"

	parsedPath, err := sszquery.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath failed: %v", err)
	}

	expectedPath := []sszquery.PathElement{
		{Name: "data"},
		{Name: "target"},
		{Name: "root"},
	}

	assert.Equal(t, 3, len(parsedPath), "Expected 3 path elements, got %d", len(parsedPath))
	assert.DeepEqual(t, expectedPath, parsedPath, "Parsed path does not match expected path")
}
