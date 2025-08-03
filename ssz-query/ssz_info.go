package sszquery

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"

	"github.com/OffchainLabs/prysm/v6/encoding/ssz"
	fastssz "github.com/prysmaticlabs/fastssz"
)

// SSZType represents the type supported by SSZ.
// https://github.com/ethereum/consensus-specs/blob/master/ssz/simple-serialize.md#typing
type SSZType int

// SSZ type constants.
const (
	// Basic types
	UintN SSZType = iota
	Byte
	Boolean

	// Composite types
	Container
	Vector
	List
	Bitvector
	Bitlist

	// Added in EIP-7916
	// TODO: Support ProgressiveList
	ProgressiveList
	// TODO: Support Union
	Union
)

func (t SSZType) String() string {
	switch t {
	case UintN:
		return "UintN"
	case Byte:
		return "Byte"
	case Boolean:
		return "Boolean"
	case Container:
		return "Container"
	case Vector:
		return "Vector"
	case List:
		return "List"
	case Bitvector:
		return "Bitvector"
	case Bitlist:
		return "Bitlist"
	case ProgressiveList:
		return "ProgressiveList"
	case Union:
		return "Union"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// sszInfo holds the pre-calculated SSZ data for a struct type.
type sszInfo struct {
	// Type of the SSZ structure (Basic, Container, List).
	sszType SSZType
	typ     reflect.Type

	// isVariable is true if the struct contains any variable-size fields.
	isVariable bool
	// fixedSize is the total size of the struct's fixed part.
	fixedSize uint64

	// For Container types:
	// fieldInfos maps a field's JSON name to its SSZ info (for nested Containers).
	fieldInfos map[string]*fieldInfo

	// For List/Vector types:
	elementInfo *sszInfo
}

type fieldInfo struct {
	sszInfo *sszInfo
	// offset is the offset of the field within the parent struct.
	offset uint64
}

func (info *sszInfo) FixedSize() uint64 {
	if info == nil {
		return 0
	}
	return info.fixedSize
}

func (info *sszInfo) UnmarshalFromSSZ(data []byte) (any, error) {
	if info == nil || info.typ == nil {
		return nil, fmt.Errorf("sszInfo or its type is nil")
	}

	newObjPtr := reflect.New(info.typ)

	unmarshaler, ok := newObjPtr.Interface().(fastssz.Unmarshaler)
	if !ok {
		// If the type is `[]byte`, we can return the raw bytes directly.
		if info.typ.Kind() == reflect.Slice && info.typ.Elem().Kind() == reflect.Uint8 {
			return data, nil
		}

		return nil, fmt.Errorf("type %v does not implement ssz.Unmarshaler", info.typ)
	}

	if err := unmarshaler.UnmarshalSSZ(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal for type %v: %w", info.typ, err)
	}

	return newObjPtr.Interface(), nil
}

func (info *sszInfo) Print() string {
	if info == nil {
		return "<nil>"
	}
	var builder strings.Builder
	printRecursive(info, &builder, "")
	return builder.String()
}

func printRecursive(info *sszInfo, builder *strings.Builder, prefix string) {
	switch info.sszType {
	case Container:
		builder.WriteString(fmt.Sprintf("%s: %s (fixedSize: %d, isVariable: %t)\n", info.sszType, info.typ.Name(), info.fixedSize, info.isVariable))
	case List, Vector:
		builder.WriteString(fmt.Sprintf("%s[%s] (fixedSize: %d, isVariable: %t)\n", info.sszType, info.elementInfo.typ.Name(), info.fixedSize, info.isVariable))
	default:
		builder.WriteString(fmt.Sprintf("%s (fixedSize: %d, isVariable: %t)\n", info.sszType, info.fixedSize, info.isVariable))
	}

	keys := make([]string, 0, len(info.fieldInfos))
	for k := range info.fieldInfos {
		keys = append(keys, k)
	}

	for i, key := range keys {
		connector := "├─"
		nextPrefix := prefix + "│  "
		if i == len(keys)-1 {
			connector = "└─"
			nextPrefix = prefix + "   "
		}

		builder.WriteString(fmt.Sprintf("%s%s %s (offset: %d) ", prefix, connector, key, info.fieldInfos[key].offset))

		if nestedInfo := info.fieldInfos[key].sszInfo; nestedInfo != nil {
			printRecursive(nestedInfo, builder, nextPrefix)
		} else {
			builder.WriteString("\n")
		}
	}
}

// Public function to compute the hash tree root of the already analyzed sszInfo with the marshalled data.
func (info *sszInfo) HashTreeRoot(marshalledData []byte) ([32]byte, error) {
	if info == nil {
		return [32]byte{}, fmt.Errorf("nil sszInfo provided")
	}

	return info.computeHashTreeRoot(marshalledData)
}

// computeHashTreeRoot switch/case per type to compute the hash tree root for the given SSZ data
// To be called recursively.
func (info *sszInfo) computeHashTreeRoot(data []byte) ([32]byte, error) {
	switch info.sszType {
	case Container:
		return info.computeContainerHashTreeRoot(data)
	case List:
		return info.computeListHashTreeRoot(data)
	case Vector:
		return info.computeVectorHashTreeRoot(data)
	case UintN, Byte, Boolean:
		return info.computeBasicHashTreeRoot(data)
	case Bitvector, Bitlist:
		return info.computeBitHashTreeRoot(data)
	default:
		return [32]byte{}, fmt.Errorf("unsupported SSZ type: %s", info.sszType)
	}
}

// computeContainerHashTreeRoot computes the hash tree root for a container
func (info *sszInfo) computeContainerHashTreeRoot(data []byte) ([32]byte, error) {
	// Sanity check: ensure data length matches the fixed size of the container
	if len(data) < int(info.fixedSize) {
		return [32]byte{}, fmt.Errorf("data too short for container: got %d, need at least %d", len(data), info.fixedSize)
	}

	// Get field names
	fieldNames := make([]string, 0, len(info.fieldInfos))
	for name := range info.fieldInfos {
		fieldNames = append(fieldNames, name)
	}

	// Compute hash for each field
	var chunks [][32]byte
	for _, fieldName := range fieldNames {
		fieldInfo := info.fieldInfos[fieldName]

		// Extract field data based on offset and field type
		fieldData, err := info.extractFieldData(data, fieldInfo)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to extract field %s: %w", fieldName, err)
		}

		fmt.Printf("Extracted field ->%s<-: %x\n", fieldName, fieldData)

		// Compute hash tree root for the field
		fieldHash, err := fieldInfo.sszInfo.computeHashTreeRoot(fieldData)
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
func (info *sszInfo) extractFieldData(data []byte, fieldInfo *fieldInfo) ([]byte, error) {
	if fieldInfo.sszInfo.isVariable {
		// For variable-length fields, we need to read the offset from the fixed part
		// and then extract the actual data from the variable part
		if len(data) < int(fieldInfo.offset+4) {
			return nil, fmt.Errorf("data too short to read offset")
		}

		// Read the offset (4 bytes little-endian)
		offset := binary.LittleEndian.Uint32(data[fieldInfo.offset : fieldInfo.offset+4])

		// Extract the variable data starting from the offset
		if int(offset) >= len(data) {
			return nil, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
		}

		// TODO: assuming only one variable-length field per container
		return data[offset:], nil
	} else {
		// For fixed-length fields, extract directly using offset and size
		size := fieldInfo.sszInfo.fixedSize
		if len(data) < int(fieldInfo.offset+size) {
			return nil, fmt.Errorf("data too short for fixed field")
		}
		return data[fieldInfo.offset : fieldInfo.offset+size], nil
	}
}

// computeListHashTreeRoot computes the hash tree root for a list
// mix_in_length(merkleize(pack(value), limit=chunk_count(type)), len(value)) if value is a list of basic objects.
func (info *sszInfo) computeListHashTreeRoot(data []byte) ([32]byte, error) {
	// Lists are variable-length, so we need to determine the number of elements
	fmt.Printf("List type: %s, fixedSize: %d, isVariable: %t\n", info.elementInfo.typ.Name(), info.fixedSize, info.isVariable)

	// TODO extend to List of Composite types
	if info.elementInfo == nil {
		return [32]byte{}, fmt.Errorf("elementInfo is nil for list type %v", info.typ)
	}

	elemSize := info.elementInfo.fixedSize // e.g. 8 for uint64
	if elemSize == 0 {
		return [32]byte{}, fmt.Errorf("invalid element size 0 for list %v", info.typ)
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
	root, err := ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), 64)

	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to merkleize: %w", err)
	}

	// Mix in the length (number of elements, not bytes)
	lengthBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBytes[:8], numElements)
	return ssz.MixInLength(root, lengthBytes), nil

}

// computeVectorHashTreeRoot computes the hash tree root for a vector
func (info *sszInfo) computeVectorHashTreeRoot(data []byte) ([32]byte, error) {
	// Vectors are fixed-length, so we can directly chunkify and merkleize
	chunks, err := ssz.PackByChunk([][]byte{data})
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to pack chunks: %w", err)
	}

	return ssz.MerkleizeVector(chunks, uint64(len(chunks))), nil
}

// computeBasicHashTreeRoot computes the hash tree root for basic types
func (info *sszInfo) computeBasicHashTreeRoot(data []byte) ([32]byte, error) {
	// For basic types, pad to 32 bytes and return
	var chunk [32]byte
	copy(chunk[:], data)
	return chunk, nil
}

// computeBitHashTreeRoot computes the hash tree root for bitvector/bitlist
func (info *sszInfo) computeBitHashTreeRoot(data []byte) ([32]byte, error) {
	// this needs proper bitfield handling
	return info.computeBasicHashTreeRoot(data)
}

// HashTreeRootHex computes the hash tree root and returns it as a hex string for debugging
func (info *sszInfo) HashTreeRootHex(marshalledData []byte) string {
	root, err := info.HashTreeRoot(marshalledData)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return fmt.Sprintf("%x", root)
}
