package state_native

import (
	"context"
	"encoding/binary"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/state/state-native/types"
	"github.com/OffchainLabs/prysm/v7/config/params"
	"github.com/OffchainLabs/prysm/v7/container/trie"
	"github.com/OffchainLabs/prysm/v7/encoding/bytesutil"
	"github.com/OffchainLabs/prysm/v7/runtime/version"
)

const (
	finalizedRootIndex = uint64(105) // Precomputed value.
)

// FinalizedRootGeneralizedIndex for the beacon state.
func FinalizedRootGeneralizedIndex() uint64 {
	return finalizedRootIndex
}

// CurrentSyncCommitteeGeneralizedIndex for the beacon state.
func (b *BeaconState) CurrentSyncCommitteeGeneralizedIndex() (uint64, error) {
	if b.version == version.Phase0 {
		return 0, errNotSupported("CurrentSyncCommitteeGeneralizedIndex", b.version)
	}

	return uint64(types.CurrentSyncCommittee.RealPosition()), nil
}

// NextSyncCommitteeGeneralizedIndex for the beacon state.
func (b *BeaconState) NextSyncCommitteeGeneralizedIndex() (uint64, error) {
	if b.version == version.Phase0 {
		return 0, errNotSupported("NextSyncCommitteeGeneralizedIndex", b.version)
	}

	return uint64(types.NextSyncCommittee.RealPosition()), nil
}

// CurrentSyncCommitteeProof from the state's Merkle trie representation.
func (b *BeaconState) CurrentSyncCommitteeProof(ctx context.Context) ([][]byte, error) {
	_, proof, err := b.ProofByFieldIndex(ctx, types.CurrentSyncCommittee)
	return proof, err
}

// NextSyncCommitteeProof from the state's Merkle trie representation.
func (b *BeaconState) NextSyncCommitteeProof(ctx context.Context) ([][]byte, error) {
	_, proof, err := b.ProofByFieldIndex(ctx, types.NextSyncCommittee)
	return proof, err
}

// FinalizedRootProof crafts a Merkle proof for the finalized root
// contained within the finalized checkpoint of a beacon state.
func (b *BeaconState) FinalizedRootProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	_, branchProof, err := b.proofByFieldIndex(ctx, types.FinalizedCheckpoint)
	if err != nil {
		return nil, err
	}

	// The epoch field of a finalized checkpoint is the neighbor
	// index of the finalized root field in its Merkle tree representation
	// of the checkpoint. This neighbor is the first element added to the proof.
	epochBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(epochBuf, uint64(b.finalizedCheckpointVal().Epoch))
	epochRoot := bytesutil.ToBytes32(epochBuf)
	proof := make([][]byte, 0)
	proof = append(proof, epochRoot[:])
	proof = append(proof, branchProof...)
	return proof, nil
}

// ProofByFieldIndex constructs proofs for given field index with lock acquisition.
// Returns the field root (leaf) and the proof hashes.
func (b *BeaconState) ProofByFieldIndex(ctx context.Context, f types.FieldIndex) ([]byte, [][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	return b.proofByFieldIndex(ctx, f)
}

// proofByFieldIndex constructs proofs for given field index.
// Important: it is assumed that beacon state mutex is locked when calling this method.
// Returns the field root (leaf) and the proof hashes.
func (b *BeaconState) proofByFieldIndex(ctx context.Context, f types.FieldIndex) ([]byte, [][]byte, error) {
	err := b.validateFieldIndex(f)
	if err != nil {
		return nil, nil, err
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, nil, err
	}

	leaf := b.merkleLayers[0][f.RealPosition()]
	proof := trie.ProofFromMerkleLayers(b.merkleLayers, f.RealPosition())
	return leaf, proof, nil
}

func (b *BeaconState) validateFieldIndex(f types.FieldIndex) error {
	switch b.version {
	case version.Phase0:
		if f.RealPosition() > params.BeaconConfig().BeaconStateFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Altair:
		if f.RealPosition() > params.BeaconConfig().BeaconStateAltairFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Bellatrix:
		if f.RealPosition() > params.BeaconConfig().BeaconStateBellatrixFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Capella:
		if f.RealPosition() > params.BeaconConfig().BeaconStateCapellaFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Deneb:
		if f.RealPosition() > params.BeaconConfig().BeaconStateDenebFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Electra:
		if f.RealPosition() > params.BeaconConfig().BeaconStateElectraFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	case version.Fulu:
		if f.RealPosition() > params.BeaconConfig().BeaconStateFuluFieldCount-1 {
			return errNotSupported(f.String(), b.version)
		}
	}

	return nil
}
