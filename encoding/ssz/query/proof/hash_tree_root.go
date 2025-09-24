package proof

import (
	"fmt"

	sszquery "github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
	ssz "github.com/prysmaticlabs/fastssz"
)

// HashTreeRoot computes the hash tree root according to the SSZ spec for any given SSZInfo object + the serialized data.
//
// The hash tree root is a cryptographic commitment to the entire data structure, used extensively
// in Ethereum's consensus layer for creating Merkle proofs and maintaining state roots. This method
// implements the SSZ hash tree root algorithm, which recursively hashes all fields and combines
// them using binary Merkle trees.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// Returns:
// - 32-byte hash tree root of the object.
// - error if any issues occur during computation.
// The method handles all SSZ-supported types including:
func HashTreeRoot(si *sszquery.SSZInfo, serializedData []byte) ([32]byte, error) {
	pool := &ssz.DefaultHasherPool

	hh := pool.Get()
	defer func() {
		pool.Put(hh)
	}()

	err := buildRootFromSSZInfo(si, serializedData, hh)
	if err != nil {
		return [32]byte{}, err
	}

	return hh.HashRoot()
}

// buildRootFromSSZInfo is the core recursive function for computing hash tree roots of Go values.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error if any issues occur during computation.
// The method handles all SSZ-supported types including:
func buildRootFromSSZInfo(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	if si == nil {
		return fmt.Errorf("nil SSZInfo")
	}

	if hh == nil {
		return fmt.Errorf("nil hasher")
	}

	// https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#typing
	switch si.Type() {
	case sszquery.Boolean, sszquery.UintN, sszquery.Byte:
		err := buildRootFromBasicType(si, serializedData, hh)
		if err != nil {
			return err
		}
	case sszquery.Vector, sszquery.Bitvector:
		err := buildRootFromVector(si, serializedData, hh)
		if err != nil {
			return err
		}
	case sszquery.List, sszquery.Bitlist, sszquery.ProgressiveList:
		err := buildRootFromList(si, serializedData, hh)
		if err != nil {
			return err
		}
	case sszquery.Union:
		err := buildRootFromCompatibleUnion(si, serializedData, hh)
		if err != nil {
			return err
		}
	case sszquery.Container:
		err := buildRootFromContainer(si, serializedData, hh)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported SSZ type %s", si.Type())
	}
	return nil
}

// buildRootFromBasicType computes the hash tree root for basic SSZ types (boolean, uintN, byte).
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error if any issues occur during computation.
func buildRootFromBasicType(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	if hh == nil {
		return fmt.Errorf("nil hasher")
	}
	// TODO: check serializedData length 0
	hashIndex := hh.Index()
	hh.PutBytes(serializedData[:si.FixedSize()])
	hh.Merkleize(hashIndex)
	return nil
}

// buildRootFromVector computes the hash tree root for ssz vectors.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error if any issues occur during computation.
func buildRootFromVector(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	if si.Type() != sszquery.Vector && si.Type() != sszquery.Bitvector {
		return fmt.Errorf("expected vector type, got %s", si.Type())
	}

	if si.Type() == sszquery.Bitvector {
		// Pack bits into bytes and merkleize for bitvector hash tree root
		hh.PutBytes(serializedData[:(si.FixedSize())])
		hh.Merkleize(hashIndex)
		return nil
	}

	vi, err := si.VectorInfo()
	if err != nil {
		return err
	}

	elemType, err := vi.Element()
	if err != nil {
		return err
	}

	vectorLength := vi.Length() // NOTE: vectorLength cannot be zero for valid SSZ vectors

	if isBasicType(elemType.Type()) {
		// Pack basic type elements into bytes and merkleize for vector hash tree root
		hh.PutBytes(serializedData[:vectorLength*elemType.Size()])
	} else {
		// Hash each composite element individually, then merkleize all hashes
		elemSize := elemType.Size()
		// Validate element size to prevent potential issues
		if elemSize == 0 {
			return fmt.Errorf("element type has zero size")
		}

		// Check if we have enough data for all vector elements
		requiredDataSize := vectorLength * elemSize
		if uint64(len(serializedData)) < requiredDataSize {
			return fmt.Errorf("insufficient data: need %d bytes, have %d", requiredDataSize, len(serializedData))
		}

		for i := uint64(0); i < vectorLength; i++ {
			elementOffset := i * elemSize
			elementData := serializedData[elementOffset : elementOffset+elemSize]

			err := buildRootFromSSZInfo(elemType, elementData, hh)
			if err != nil {
				return fmt.Errorf("failed to hash vector element %d: %w", i, err)
			}
		}
	}
	hh.Merkleize(hashIndex)
	return nil
}

// buildRootFromList computes the hash tree root for ssz lists.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error if any issues occur during computation.
func buildRootFromList(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	if si.Type() != sszquery.List && si.Type() != sszquery.Bitlist {
		if si.Type() != sszquery.ProgressiveList {
			return fmt.Errorf("progressive list root is yet to be implemented")
		} else {
			return fmt.Errorf("expected list type, got %s", si.Type())
		}
	}

	if si.Type() == sszquery.Bitlist {
		bi, err := si.BitlistInfo()
		if err != nil {
			return err
		}
		if bi.Length() == 0 {
			return fmt.Errorf("bitlist length is zero")
		}

		bitlistLimit := bi.Limit()
		hh.PutBitlist(serializedData, bitlistLimit)
		return nil
	}

	li, err := si.ListInfo()
	if err != nil {
		return err
	}

	elemType, err := li.Element()
	if err != nil {
		return err
	}

	listLimit := li.Limit()
	if listLimit == 0 {
		return fmt.Errorf("list limit is zero")
	}

	listLength := li.Length()
	if listLength == 0 {
		// empty list - still needs length mixing for proper list hash
		// Calculate chunk limit for consistency
		if isBasicType(elemType.Type()) {
			hh.MerkleizeWithMixin(hashIndex, 0, ssz.CalculateLimit(listLimit, listLength, elemType.Size()))
		} else {
			hh.MerkleizeWithMixin(hashIndex, 0, listLimit)
		}
		return nil
	}

	// serializedData already contains just the list data (offset has been dereferenced by caller)
	// so we start from the beginning of the data

	if isBasicType(elemType.Type()) {
		// pack(values): Given ordered objects of the same basic type:
		// 	- Serialize values into bytes.
		// 	- If not aligned to a multiple of BYTES_PER_CHUNK bytes, right-pad with zeroes to the next multiple.
		// 	- Partition the bytes into BYTES_PER_CHUNK-byte chunks.
		// 	- Return the chunks.
		// merkleize(pack(value)) if value is a basic object or a vector of basic objects.
		// mix_in_length(merkleize(pack(value), limit=chunk_count(type)), len(value)) if value is a list of basic objects.
		// mix_in_length: Given a Merkle root and a length ("uint256" little-endian serialization) return hash(root + length).
		hh.Append(serializedData[:listLength*elemType.Size()])

		// For basic types, calculate the maximum number of chunks based on element size
		elemSize := elemType.Size()
		hh.MerkleizeWithMixin(hashIndex, listLength, ssz.CalculateLimit(listLimit, listLength, elemSize))
	} else {
		// mix_in_length(merkleize([hash_tree_root(element) for element in value], limit=chunk_count(type)), len(value)) if value is a list of composite objects.
		// For composite types, hash each element individually, then merkleize with length mixing
		elemSize := elemType.Size()
		for i := uint64(0); i < listLength; i++ {
			elementOffset := i * elemSize
			elementData := serializedData[elementOffset : elementOffset+elemSize]

			err := buildRootFromSSZInfo(elemType, elementData, hh)
			if err != nil {
				return fmt.Errorf("failed to hash list element %d: %w", i, err)
			}
		}
		// For composite types, each element becomes one chunk after hashing
		hh.MerkleizeWithMixin(hashIndex, listLength, listLimit)
	}

	return nil
}

// buildRootFromCompatibleUnion computes the hash tree root for CompatibleUnion values.
//
// Parameters:
// Returns:
// The method handles all SSZ-supported types including:
// Example:
func buildRootFromCompatibleUnion(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	return nil
}

// buildRootFromContainer computes the hash tree root for ssz containers.
//
// Parameters:
// Returns:
// The method handles all SSZ-supported types including:
// Example:
func buildRootFromContainer(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	if si.Type() != sszquery.Container {
		return fmt.Errorf("expected container type, got %s", si.Type())
	}

	ci, err := si.ContainerInfo()
	if err != nil {
		return err
	}

	for _, fieldName := range ci.Order() {
		fieldInfo, ok := ci.Fields()[fieldName]
		if !ok {
			return fmt.Errorf("field %s not found in container fields", fieldName)
		}

		fieldType := fieldInfo.SSZ()
		if fieldType == nil {
			return fmt.Errorf("field %s has nil SSZInfo", fieldName)
		}

		fieldOffset := fieldInfo.Offset()
		fieldSize := fieldType.Size()
		// if fieldSize == 0 {
		// 	return nil
		// }

		err := buildRootFromSSZInfo(fieldType, serializedData[fieldOffset:fieldOffset+fieldSize], hh)
		if err != nil {
			return fmt.Errorf("failed to hash container field %s: %w", fieldName, err)
		}
	}

	hh.Merkleize(hashIndex)

	return nil
}

// --- Helpers ---
func isBasicType(t sszquery.SSZType) bool {
	switch t {
	case sszquery.Boolean, sszquery.UintN, sszquery.Byte:
		return true
	default:
		return false
	}
}
