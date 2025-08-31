package proof_test

import (
	"fmt"
	"testing"

	sszquery "github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
	proof "github.com/OffchainLabs/prysm/v6/encoding/ssz/query/proof"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/testing/assert"
	"github.com/OffchainLabs/prysm/v6/testing/require"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestHashTreeRootBasicTypes(t *testing.T) {
	info, err := sszquery.AnalyzeObject(&ethpb.Checkpoint{})
	require.NoError(t, err)

	fmt.Printf("SSZ Info for BlobIdentifier: %v\n", info)
	info.Print()

	// Construct IndexedAttestationElectra with dummy data.
	dummyRoot, err := hexutil.Decode("0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2")
	require.NoError(t, err)

	blobId := &ethpb.Checkpoint{
		Epoch: 7,
		Root:  dummyRoot,
	}
	marshalledBlobId, err := blobId.MarshalSSZ()
	require.NoError(t, err)

	println("marshalledBlobId", marshalledBlobId)

	require.Equal(t, 40, len(marshalledBlobId)) // BlobIdentifier{Index:1} must marshal to 40 bytes

	// // Expect exact SSZ bytes for uint64(1) in LE:
	// assert.Equal(t,
	// 	[]byte{0x01, 0, 0, 0, 0, 0, 0, 0},
	// 	marshalledBlobId,
	// )

	// hashTreeRoot := proof.HashTreeRootHex(info, marshalledBlobId)

	// assert.Equal(t, "0100000000000000000000000000000000000000000000000000000000000000", hashTreeRoot)

}

func TestRoundTripSszInfoWithMerkle(t *testing.T) {
	// Start with a pointer to empty object and calculate SSZ info of `IndexedAttestationElectra`.
	info, err := sszquery.AnalyzeObject(&ethpb.IndexedAttestationElectra{})
	require.NoError(t, err)

	// Print the SSZ info for debugging.
	println(info.Print())

	assert.NotNil(t, info, "Expected non-nil SSZ info")

	// Construct IndexedAttestationElectra with dummy data.
	dummyRoot, err := hexutil.Decode("0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2")
	require.NoError(t, err)
	dummySignature, err := hexutil.Decode("0xc3a2f7d9e4a1b0c8d5e6f1a0b3c7d0e9f8a7b6c5d4e3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e28b7c6d5e4f3a2b1c0d9e8f7a6b5c")
	require.NoError(t, err)
	expectedTargetRoot, err := hexutil.Decode("0x4242424242424242424242424242424242424242424242424242424242424242")
	require.NoError(t, err)

	indexedAtt := &ethpb.IndexedAttestationElectra{
		AttestingIndices: []uint64{1, 2, 3},
		Data: &ethpb.AttestationData{
			Slot:            4,
			CommitteeIndex:  5,
			BeaconBlockRoot: dummyRoot,
			Source: &ethpb.Checkpoint{
				Epoch: 7,
				Root:  dummyRoot,
			},
			Target: &ethpb.Checkpoint{
				Epoch: 9,
				Root:  expectedTargetRoot,
			},
		},
		Signature: dummySignature,
	}
	marshalledIndexedAtt, err := indexedAtt.MarshalSSZ()
	require.NoError(t, err)

	hashTreeRoot := proof.HashTreeRootHex(info, marshalledIndexedAtt)

	assert.Equal(t, "cfa6677fc85ca14fc66d6b955313edaad105d6407653c222bc8a2578d59f8e6c", hashTreeRoot)

}
