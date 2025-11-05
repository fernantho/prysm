package state_native

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/state/state-native/types"
	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/container/trie"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/OffchainLabs/prysm/v6/encoding/ssz"
	"github.com/OffchainLabs/prysm/v6/math"
	"github.com/OffchainLabs/prysm/v6/runtime/version"
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
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("CurrentSyncCommitteeProof", b.version)
	}

	// In case the Merkle layers of the trie are not populated, we need
	// to perform some initialization.
	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	// Our beacon state uses a "dirty" fields pattern which requires us to
	// recompute branches of the Merkle layers that are marked as dirty.
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	return trie.ProofFromMerkleLayers(b.merkleLayers, types.CurrentSyncCommittee.RealPosition()), nil
}

// NextSyncCommitteeProof from the state's Merkle trie representation.
func (b *BeaconState) NextSyncCommitteeProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("NextSyncCommitteeProof", b.version)
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	return trie.ProofFromMerkleLayers(b.merkleLayers, types.NextSyncCommittee.RealPosition()), nil
}

// FinalizedRootProof crafts a Merkle proof for the finalized root
// contained within the finalized checkpoint of a beacon state.
func (b *BeaconState) FinalizedRootProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("FinalizedRootProof", b.version)
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	cpt := b.finalizedCheckpointVal()
	// The epoch field of a finalized checkpoint is the neighbor
	// index of the finalized root field in its Merkle tree representation
	// of the checkpoint. This neighbor is the first element added to the proof.
	epochBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(epochBuf, uint64(cpt.Epoch))
	epochRoot := bytesutil.ToBytes32(epochBuf)
	proof := make([][]byte, 0)
	proof = append(proof, epochRoot[:])
	branch := trie.ProofFromMerkleLayers(b.merkleLayers, types.FinalizedCheckpoint.RealPosition())
	proof = append(proof, branch...)
	return proof, nil
}

func (b *BeaconState) ProofByFieldIndex(ctx context.Context, f types.FieldIndex) ([][]byte, error) {
	return b.proofByFieldIndex(ctx, f)
}

// proofByFieldIndex constructs proofs for given field index.
// Important: it is assumed that beacon state mutex is locked when calling this method.
func (b *BeaconState) proofByFieldIndex(ctx context.Context, f types.FieldIndex) ([][]byte, error) {
	err := b.validateFieldIndex(f)
	if err != nil {
		return nil, err
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	return trie.ProofFromMerkleLayers(b.merkleLayers, f.RealPosition()), nil
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

// ProofsByGeneralizedIndices constructs a multi-proof for the provided generalized indices.
func (b *BeaconState) ProofsByGeneralizedIndices(ctx context.Context, gindices []uint64) (types.MultiProof, error) {
	var proof types.MultiProof

	// Input validation.
	if len(gindices) == 0 {
		return proof, fmt.Errorf("no generalized indices provided")
	}

	// Lock the beacon state for the duration of the proof generation.
	b.lock.Lock()
	defer b.lock.Unlock()

	// Get the fields included in the current version of the beacon state.
	fields := fieldsForVersion(b.version)
	if len(fields) == 0 {
		return proof, fmt.Errorf("unsupported state version %d", b.version)
	}

	// Precompute values involved in the proof generation
	fieldCount := uint64(len(fields))
	// Top-level fields depth in the Merkle Tree.
	// depthTop := ssz.Depth(fieldCount)
	base := math.PowerOf2(fieldCount)

	// Compute top-level fields proofs first.
	// 1. Initialize merkle layers.
	if err := b.initializeMerkleLayers(ctx); err != nil {
		return proof, err
	}

	// 2. Recompute dirty fields.
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return proof, err
	}

	proof.Indices = make([]uint64, 0, len(gindices))
	proof.Leaves = make([][]byte, 0, len(gindices))

	// seenProofs := make(map[string]struct{})
	orderedProofs := make([][]byte, 0)

	for _, gi := range gindices {
		parentField, err := b.parentFieldFromGIndex(gi)
		if err != nil {
			return types.MultiProof{}, err
		}
		// Determine if the generalized index points to a top-level field
		// or a nested field. GI MUST always points to a terminal node.
		if gi <= base {
			// top-level field
			computedProof, err := b.proofByFieldIndex(ctx, parentField)
			if err != nil {
				return types.MultiProof{}, err
			}
			proof.Proofs = append(proof.Proofs, computedProof...)
			proof.Indices = append(proof.Indices, gi)
			leaves, err := b.ValueByFieldIndex(parentField)
			if err != nil {
				return types.MultiProof{}, err
			}
			proof.Leaves = append(proof.Leaves, leaves.([]byte))

		} else {
			// 1. recompute the field trie
			b.stateFieldLeaves[parentField].RecomputeTrie([]uint64{gi}, parentField)
			// 2. generate the proof from the field trie
			fieldTrieLayers := b.stateFieldLeaves[parentField].GetFieldLayers()

			fmt.Printf("the fields layers are: %+v\n", fieldTrieLayers)
			// proof.Proofs = append(proof.Proofs, computedProof...)
			proof.Indices = append(proof.Indices, gi)
			leaves, err := b.ValueByFieldIndex(parentField)
			if err != nil {
				return types.MultiProof{}, err
			}
			proof.Leaves = append(proof.Leaves, leaves.([]byte))
		}
	}
	proof.Proofs = orderedProofs
	return proof, nil
}

func (b *BeaconState) parentFieldFromGIndex(g uint64) (types.FieldIndex, error) {
	if g < 2 {
		return 0, fmt.Errorf("gindex %d no apunta a un campo", g)
	}
	fields := fieldsForVersion(b.version)
	if len(fields) == 0 {
		return 0, fmt.Errorf("unsupported state version %d", b.version)
	}
	fieldCount := uint64(len(fields))
	depthTop := ssz.Depth(fieldCount)
	base := nextPowerOfTwo(fieldCount)
	depth := bits.Len64(g) - 1
	if depth < int(depthTop) {
		return 0, fmt.Errorf("gindex %d está por encima del estado", g)
	}
	ancestor := g
	for ancestor >= base+fieldCount || ancestor < base {
		ancestor /= 2
		if ancestor == 0 {
			return 0, fmt.Errorf("no se pudo determinar el campo padre para gindex %d", g)
		}
	}
	offset := ancestor - base
	if offset >= uint64(len(fields)) {
		return 0, fmt.Errorf("offset %d fuera de rango", offset)
	}
	return fields[11], nil
}

// fieldsForVersion returns the ordered list of beacon-state fields for the provided fork version.
func fieldsForVersion(ver int) []types.FieldIndex {
	switch ver {
	case version.Phase0:
		return phase0Fields
	case version.Altair:
		return altairFields
	case version.Bellatrix:
		return bellatrixFields
	case version.Capella:
		return capellaFields
	case version.Deneb:
		return denebFields
	case version.Electra:
		return electraFields
	case version.Fulu:
		return fuluFields
	default:
		return nil
	}
}

func (b *BeaconState) ValueByFieldIndex(field types.FieldIndex) (interface{}, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	switch field {
	case types.GenesisTime:
		return b.genesisTime, nil
	case types.GenesisValidatorsRoot:
		return bytesutil.ToBytes32(b.genesisValidatorsRoot[:]), nil // copy
	case types.Slot:
		return uint64(b.slot), nil
	// case types.Fork:
	// 	if b.fork == nil {
	// 		return nil, nil
	// 	}
	// 	// clone proto
	// 	return proto.Clone(b.fork).(*ethpb.Fork), nil
	// case types.LatestBlockHeader:
	// 	if b.latestBlockHeader == nil {
	// 		return nil, nil
	// 	}
	// 	return proto.Clone(b.latestBlockHeader).(*ethpb.BeaconBlockHeader), nil
	case types.BlockRoots:
		return b.blockRootsVal().Slice(), nil // or clone each [32]byte
	case types.StateRoots:
		return b.stateRootsVal().Slice(), nil
	case types.HistoricalRoots:
		// return copy of slice of [32]byte
	case types.Eth1DataVotes:
		// these are lists managed by state; use b.eth1DataVotes or b.stateFieldLeaves
		return b.eth1DataVotes, nil // or clone
	case types.Validators:
		return b.validatorsVal(), nil // validatorsVal already returns clones
	case types.Balances:
		return b.balancesMultiValue.Value(b), nil // returns []uint64
	// ... handle other cases similarly ...
	default:
		return nil, fmt.Errorf("unsupported field %v", field)
	}
	return nil, fmt.Errorf("unsupported field %v", field)
}
