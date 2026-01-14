package query_test

import (
	"context"
	"testing"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/OffchainLabs/prysm/v7/consensus-types/blocks"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz/query"
	eth "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	sszquerypb "github.com/OffchainLabs/prysm/v7/proto/ssz_query/testing"
	"github.com/OffchainLabs/prysm/v7/testing/require"
	"github.com/OffchainLabs/prysm/v7/testing/util"
	ssz "github.com/prysmaticlabs/fastssz"
)

func TestProve_FixedNestedContainer(t *testing.T) {
	value2 := make([]byte, 32)
	for i := range value2 {
		value2[i] = byte(i + 1)
	}

	obj := &sszquerypb.FixedNestedContainer{
		Value1: 123,
		Value2: value2,
	}

	tests := []string{
		".value1",
		".value2",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			proveAndVerify(t, obj, tc)
		})
	}
}

func TestProve_VariableTestContainer(t *testing.T) {
	obj := createVariableTestContainer()

	tests := []string{
		".leading_field",
		".field_list_uint64[2]",
		"len(field_list_uint64)",
		".nested.nested_list_field[1]",
		".variable_container_list[0].inner_1.field_list_uint64[1]",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			proveAndVerify(t, obj, tc)
		})
	}
}

func TestProve_BeaconBlock(t *testing.T) {
	randaoReveal := make([]byte, 96)
	for i := range randaoReveal {
		randaoReveal[i] = 0x42
	}
	root32 := make([]byte, 32)
	for i := range root32 {
		root32[i] = 0x24
	}
	sig := make([]byte, 96)
	for i := range sig {
		sig[i] = 0x99
	}

	att := &eth.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth.AttestationData{
			Slot:            1,
			CommitteeIndex:  1,
			BeaconBlockRoot: root32,
			Source: &eth.Checkpoint{
				Epoch: 1,
				Root:  root32,
			},
			Target: &eth.Checkpoint{
				Epoch: 1,
				Root:  root32,
			},
		},
		Signature: sig,
	}

	b := util.NewBeaconBlock()
	b.Block.Slot = 123
	b.Block.Body.RandaoReveal = randaoReveal
	b.Block.Body.Attestations = []*eth.Attestation{att}

	sb, err := blocks.NewSignedBeaconBlock(b)
	require.NoError(t, err)

	protoBlock, err := sb.Block().Proto()
	require.NoError(t, err)

	obj, ok := protoBlock.(query.SSZObject)
	require.Equal(t, true, ok, "block proto does not implement query.SSZObject")

	tests := []string{
		".slot",
		".body.randao_reveal",
		".body.attestations[0].data.slot",
		"len(body.attestations)",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			proveAndVerify(t, obj, tc)
		})
	}
}

func TestProve_BeaconState(t *testing.T) {
	ctx := context.Background()
	st, _ := util.DeterministicGenesisState(t, 16)
	require.NoError(t, st.SetSlot(primitives.Slot(42)))

	sszObj, ok := st.ToProtoUnsafe().(query.SSZObject)
	require.Equal(t, true, ok, "state proto does not implement query.SSZObject")

	// Sanity check the proto-state root matches the state root.
	stateRoot, err := st.HashTreeRoot(ctx)
	require.NoError(t, err)
	protoRoot, err := sszObj.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, stateRoot, protoRoot)

	tests := []string{
		".slot",
		".latest_block_header",
		".validators[0].effective_balance",
		"len(validators)",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			proveAndVerify(t, sszObj, tc)
		})
	}
}

// proveAndVerify helper to analyze an object, generate a merkle proof for the given path,
// and verify the proof against the object's root.
func proveAndVerify(t *testing.T, obj query.SSZObject, pathStr string) (*ssz.Proof, uint64) {
	t.Helper()

	info, err := query.AnalyzeObject(obj)
	require.NoError(t, err)

	path, err := query.ParsePath(pathStr)
	require.NoError(t, err)

	gi, err := query.GetGeneralizedIndexFromPath(info, path)
	require.NoError(t, err)

	proof, err := info.Prove(gi)
	require.NoError(t, err)
	require.Equal(t, int(gi), proof.Index)

	root, err := obj.HashTreeRoot()
	require.NoError(t, err)

	ok, err := ssz.VerifyProof(root[:], proof)
	require.NoError(t, err)
	require.Equal(t, true, ok, "merkle proof verification failed")

	require.Equal(t, 32, len(proof.Leaf))
	for i, h := range proof.Hashes {
		require.Equal(t, 32, len(h), "proof hash %d is not 32 bytes", i)
	}

	return proof, gi
}
