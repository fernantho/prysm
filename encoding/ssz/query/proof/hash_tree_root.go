package proof

import (
	"encoding/binary"
	"fmt"

	"github.com/OffchainLabs/prysm/v6/encoding/ssz"
	sszquery "github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
)

// Public function to compute the hash tree root for a given sszInfo struct
// and a given byte slice containing the marshalled data. Entry point for external calls.
func HashTreeRoot(info *sszquery.SSZInfo, marshalledData []byte) ([32]byte, error) {
	if info == nil {
		return [32]byte{}, fmt.Errorf("nil sszInfo provided")
	}

	if len(marshalledData) == 0 {
		return [32]byte{}, fmt.Errorf("empty marshalled data")
	}

	return computeHashTreeRoot(info, marshalledData)
}

// computeHashTreeRoot switch/case per type to compute the hash tree root for the given SSZ data
// To be called recursively.
func computeHashTreeRoot(info *sszquery.SSZInfo, data []byte) ([32]byte, error) {
	switch info.Type() {
	case sszquery.Container:
		return computeContainerHashTreeRoot(info, data)
	case sszquery.List:
		return computeListHashTreeRoot(info, data)
	case sszquery.Vector:
		return computeVectorHashTreeRoot(data)
	case sszquery.UintN, sszquery.Byte, sszquery.Boolean:
		return computeBasicHashTreeRoot(data)
	case sszquery.Bitvector, sszquery.Bitlist:
		return computeBitHashTreeRoot(data)
	default:
		return [32]byte{}, fmt.Errorf("unsupported SSZ type: %s", info.Type())
	}
}

// computeContainerHashTreeRoot computes the hash tree root for a container
func computeContainerHashTreeRoot(info *sszquery.SSZInfo, data []byte) ([32]byte, error) {
	// Sanity check: ensure data length matches the fixed size of the container
	if len(data) < int(info.FixedSize()) {
		return [32]byte{}, fmt.Errorf("data too short for container: got %d, need at least %d", len(data), info.FixedSize())
	}

	// Get field names
	containerInfo, err := info.ContainerInfo()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get container info: %w", err)
	}
	fieldNames := make([]string, 0, len(containerInfo))
	for name := range containerInfo {
		fieldNames = append(fieldNames, name)
	}

	// Compute hash for each field
	var chunks [][32]byte
	for _, fieldName := range fieldNames {
		fieldInfo := containerInfo[fieldName]

		// Extract field data based on offset and field type
		fieldData, err := extractFieldData(fieldInfo, data, info)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to extract field %s: %w", fieldName, err)
		}

		fmt.Printf("Extracted field ->%s<-: %x\n", fieldName, fieldData)

		// Compute hash tree root for the field
		fieldHash, err := computeHashTreeRoot(fieldInfo.SSZ(), fieldData)
		fmt.Printf("Computed hash for field %s: %x\n", fieldName, fieldHash)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to compute hash for field %s: %w", fieldName, err)
		}

		chunks = append(chunks, fieldHash)
	}

	// Merkleize the chunks
	return ssz.MerkleizeVector(chunks, uint64(len(chunks))), nil // TODO
}

// extractFieldData extracts the data for a specific field from the serialized container data
func extractFieldData(fieldInfo *sszquery.FieldInfo, data []byte, _ *sszquery.SSZInfo) ([]byte, error) {
	if fieldInfo.SSZ().IsVariable() {
		// For variable-length fields, we need to read the offset from the fixed part
		// and then extract the actual data from the variable part
		if len(data) < int(fieldInfo.Offset()+4) {
			return nil, fmt.Errorf("data too short to read offset")
		}

		// Read the offset (4 bytes little-endian)
		offset := binary.LittleEndian.Uint32(data[fieldInfo.Offset() : fieldInfo.Offset()+4]) // TODO ?:: replace for converter as https://github.com/syjn99/prysm/blob/de871518ee9fb7df182eda531bf078c2c96445cb/ssz-query/ssz_info.go#L137

		// Extract the variable data starting from the offset
		if int(offset) >= len(data) {
			return nil, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
		}

		// TODO: assuming only one variable-length field per container
		return data[offset:], nil
	} else {
		// For fixed-length fields, extract directly using offset and size
		size := fieldInfo.SSZ().FixedSize()
		if len(data) < int(fieldInfo.Offset()+size) {
			return nil, fmt.Errorf("data too short for fixed field")
		}
		return data[fieldInfo.Offset() : fieldInfo.Offset()+size], nil
	}
}

// computeListHashTreeRoot computes the hash tree root for a list
// mix_in_length(merkleize(pack(value), limit=chunk_count(type)), len(value)) if value is a list of basic objects.
func computeListHashTreeRoot(info *sszquery.SSZInfo, data []byte) ([32]byte, error) {
	// Lists are variable-length, so we need to determine the number of elements
	fmt.Printf("List type: %s, fixedSize: %d, isVariable: %t\n", info.Type(), info.FixedSize(), info.IsVariable())

	// TODO extend to List of Composite types
	listInfo, err := sszquery.AnalyzeObject(info.Type())
	if err != nil {
		return [32]byte{}, fmt.Errorf("elementInfo is nil for list type %v", info.Type())
	}

	elemSize := listInfo.FixedSize()
	if elemSize == 0 {
		return [32]byte{}, fmt.Errorf("invalid element size 0 for list %v", info.Type())
	}
	numElements := uint64(len(data)) / elemSize

	// Inspiration: https://github.com/syjn99/prysm/blob/077bc23fedcced4a0d963266ffdedf5042adeaa4/consensus-types/blocks/proofs.go#L165-L181

	// 2. Pack basic elements into 32‑byte chunks
	chunks, err := ssz.PackByChunk([][]byte{data})
	if err != nil {
		return [32]byte{}, fmt.Errorf("pack error: %w", err)
	}

	fmt.Printf("Packed chunks: %d chunks: %v\n", len(chunks), chunks)

	// Compute the merkle root of the chunks
	// limit := uint64(64)
	limit := uint64(32768) // This is the maximum number of chunks for a list |
	// - `List[B, N]` and `Vector[B, N]`, where `B` is a basic type:
	//   `(N * size_of(B) + 31) // 32` (dividing by chunk size, rounding up)
	root, err := ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), limit)

	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to merkleize: %w", err)
	}

	// Mix in the length (number of elements, not bytes)
	lengthBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBytes[:8], numElements)
	return ssz.MixInLength(root, lengthBytes), nil
}

// computeVectorHashTreeRoot computes the hash tree root for a vector
func computeVectorHashTreeRoot(data []byte) ([32]byte, error) {
	// Vectors are fixed-length, so we can directly chunkify and merkleize
	chunks, err := ssz.PackByChunk([][]byte{data})
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to pack chunks: %w", err)
	}

	return ssz.MerkleizeVector(chunks, uint64(len(chunks))), nil
}

// computeBasicHashTreeRoot computes the hash tree root for basic types
func computeBasicHashTreeRoot(data []byte) ([32]byte, error) {
	// For basic types, pad to 32 bytes and return
	var chunk [32]byte
	copy(chunk[:], data)
	return chunk, nil
}

// computeBitHashTreeRoot computes the hash tree root for bitvector/bitlist
func computeBitHashTreeRoot(data []byte) ([32]byte, error) {
	// this needs proper bitfield handling
	return computeBasicHashTreeRoot(data)
}

// HashTreeRootHex computes the hash tree root and returns it as a hex string for debugging
func HashTreeRootHex(info *sszquery.SSZInfo, marshalledData []byte) string {
	root, err := HashTreeRoot(info, marshalledData)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	aux := fmt.Sprintf("%x", root)
	return aux
}
