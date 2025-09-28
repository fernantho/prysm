package proof

import (
	"fmt"

	sszquery "github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
	ssz "github.com/prysmaticlabs/fastssz"
)

// HashTreeRoot computes the hash tree root according to the SSZ spec for any given SSZInfo object and its serialized data.
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
		return fmt.Errorf("buildRootFromSSZInfo: SSZInfo cannot be nil")
	}

	if hh == nil {
		return fmt.Errorf("buildRootFromSSZInfo: hasher cannot be nil")
	}

	if serializedData == nil {
		return fmt.Errorf("buildRootFromSSZInfo: serializedData cannot be nil")
	}

	// https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#typing
	switch si.Type() {
	case sszquery.Boolean, sszquery.UintN, sszquery.Byte:
		return buildRootFromBasicType(si, serializedData, hh)
	case sszquery.Vector, sszquery.Bitvector:
		return buildRootFromVector(si, serializedData, hh)
	case sszquery.List, sszquery.Bitlist, sszquery.ProgressiveList:
		return buildRootFromList(si, serializedData, hh)
	case sszquery.Union:
		return buildRootFromCompatibleUnion(si, serializedData, hh)
	case sszquery.Container:
		return buildRootFromContainer(si, serializedData, hh)
	default:
		return fmt.Errorf("buildRootFromSSZInfo: unsupported SSZ type %s, expected one of: Boolean, UintN, Byte, Vector, Bitvector, List, Bitlist, ProgressiveList, Union, Container", si.Type())
	}
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
		return fmt.Errorf("buildRootFromBasicType: hasher cannot be nil")
	}

	fixedSize := si.FixedSize()
	if uint64(len(serializedData)) < fixedSize {
		return fmt.Errorf("buildRootFromBasicType: insufficient data for %s type, need %d bytes but have %d bytes", si.Type(), fixedSize, len(serializedData))
	}

	hashIndex := hh.Index()
	hh.PutBytes(serializedData[:fixedSize])
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
	vectorType := si.Type()

	// Validate vector type early
	if vectorType != sszquery.Vector && vectorType != sszquery.Bitvector {
		return fmt.Errorf("buildRootFromVector: expected Vector or Bitvector type, got %s", vectorType)
	}

	if vectorType == sszquery.Bitvector {
		return buildRootFromBitvector(si, serializedData, hh)
	}

	return buildRootFromRegularVector(si, serializedData, hh)
}

// buildRootFromBitvector handles hash tree root computation specifically for bitvectors.
func buildRootFromBitvector(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	fixedSize := si.FixedSize()
	if uint64(len(serializedData)) < fixedSize {
		return fmt.Errorf("buildRootFromBitvector: insufficient data for Bitvector, need %d bytes but have %d bytes", fixedSize, len(serializedData))
	}

	// Pack bits into bytes and merkleize for bitvector hash tree root
	hh.PutBytes(serializedData[:fixedSize])
	hh.Merkleize(hashIndex)
	return nil
}

// buildRootFromRegularVector handles hash tree root computation for regular vectors.
func buildRootFromRegularVector(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	vi, err := si.VectorInfo()
	if err != nil {
		return fmt.Errorf("buildRootFromRegularVector: failed to get vector info: %w", err)
	}

	elemType, err := vi.Element()
	if err != nil {
		return fmt.Errorf("buildRootFromRegularVector: failed to get element type info: %w", err)
	}

	vectorLength := vi.Length()
	if vectorLength == 0 {
		return fmt.Errorf("buildRootFromRegularVector: invalid vector configuration, length cannot be zero")
	}

	elemSize := elemType.Size()
	elemTypeValue := elemType.Type()
	isBasic := isBasicType(elemTypeValue)

	if elemSize == 0 {
		return fmt.Errorf("buildRootFromRegularVector: element type %s has zero size, cannot process vector elements", elemTypeValue)
	}

	requiredDataSize := vectorLength * elemSize
	if uint64(len(serializedData)) < requiredDataSize {
		return fmt.Errorf("buildRootFromRegularVector: insufficient data for Vector[%s, %d], need %d bytes but have %d bytes", elemTypeValue, vectorLength, requiredDataSize, len(serializedData))
	}

	if isBasic {
		return buildRootFromBasicVector(hashIndex, serializedData, requiredDataSize, hh)
	}

	return buildRootFromCompositeVector(hashIndex, vectorLength, elemSize, elemType, elemTypeValue, serializedData, hh)
}

// buildRootFromBasicVector handles hash tree root computation for vectors of basic types.
func buildRootFromBasicVector(hashIndex int, serializedData []byte, requiredDataSize uint64, hh *ssz.Hasher) error {
	// Pack basic type elements into bytes and merkleize for vector hash tree root
	hh.PutBytes(serializedData[:requiredDataSize])
	hh.Merkleize(hashIndex)
	return nil
}

// buildRootFromCompositeVector handles hash tree root computation for vectors of composite types.
func buildRootFromCompositeVector(hashIndex int, vectorLength, elemSize uint64, elemType *sszquery.SSZInfo, elemTypeValue sszquery.SSZType, serializedData []byte, hh *ssz.Hasher) error {
	// Hash each composite element individually, then merkleize all hashes
	for i := uint64(0); i < vectorLength; i++ {
		elementOffset := i * elemSize
		elementData := serializedData[elementOffset : elementOffset+elemSize]

		err := buildRootFromSSZInfo(elemType, elementData, hh)
		if err != nil {
			return fmt.Errorf("buildRootFromCompositeVector: failed to hash vector element %d of type %s: %w", i, elemTypeValue, err)
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
	listType := si.Type()

	// Validate list type early
	if listType == sszquery.ProgressiveList {
		return fmt.Errorf("buildRootFromList: ProgressiveList hash tree root computation is not yet implemented")
	}

	if listType != sszquery.List && listType != sszquery.Bitlist {
		return fmt.Errorf("buildRootFromList: expected List or Bitlist type, got %s", listType)
	}

	if listType == sszquery.Bitlist {
		return buildRootFromBitlist(si, serializedData, hh)
	}

	return buildRootFromRegularList(si, serializedData, hh)
}

// buildRootFromBitlist handles hash tree root computation specifically for bitlists.
func buildRootFromBitlist(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	bi, err := si.BitlistInfo()
	if err != nil {
		return fmt.Errorf("buildRootFromBitlist: failed to get bitlist info: %w", err)
	}

	bitlistLimit := bi.Limit()
	bitlistLength := bi.Length()

	if bitlistLimit == 0 {
		return fmt.Errorf("buildRootFromBitlist: invalid bitlist configuration, limit cannot be zero")
	}

	if len(serializedData) == 0 {
		return fmt.Errorf("buildRootFromBitlist: serialized data for bitlist cannot be of length 0, expected %d", bitlistLength+1) // Expected bitlist length + 1 bitlist delimiter
	}

	hh.PutBitlist(serializedData, bitlistLimit)
	return nil
}

// buildRootFromRegularList handles hash tree root computation for regular lists.
func buildRootFromRegularList(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	li, err := si.ListInfo()
	if err != nil {
		return fmt.Errorf("buildRootFromRegularList: failed to get list info: %w", err)
	}

	elemType, err := li.Element()
	if err != nil {
		return fmt.Errorf("buildRootFromRegularList: failed to get element type info: %w", err)
	}

	listLimit := li.Limit()
	if listLimit == 0 {
		return fmt.Errorf("buildRootFromRegularList: invalid list configuration, limit cannot be zero")
	}

	listLength := li.Length()
	// Handle empty list case
	if listLength == 0 {
		return buildRootFromEmptyList(hashIndex, listLimit, elemType, hh)
	}

	// Cache frequently accessed values
	elemSize := elemType.Size()
	elemTypeValue := elemType.Type()
	isBasic := isBasicType(elemTypeValue)

	if elemSize == 0 {
		return fmt.Errorf("buildRootFromRegularList: element type %s has zero size, cannot process list elements", elemTypeValue)
	}

	requiredDataSize := listLength * elemSize
	if uint64(len(serializedData)) < requiredDataSize {
		return fmt.Errorf("buildRootFromRegularList: insufficient data for List[%s, %d] with %d elements, need %d bytes but have %d bytes", elemTypeValue, listLimit, listLength, requiredDataSize, len(serializedData))
	}

	if isBasic {
		return buildRootFromBasicList(hashIndex, listLimit, listLength, elemSize, serializedData, requiredDataSize, hh)
	}

	return buildRootFromCompositeList(hashIndex, listLimit, listLength, elemSize, elemType, elemTypeValue, serializedData, hh)
}

// buildRootFromEmptyList handles the special case of empty lists.
func buildRootFromEmptyList(hashIndex int, listLimit uint64, elemType *sszquery.SSZInfo, hh *ssz.Hasher) error {
	// Empty list still needs length mixing for proper list hash tree root
	if isBasicType(elemType.Type()) {
		// For basic types in empty lists, we use 0 as both length and limit calculation
		// since CalculateLimit with length=0 should return the base limit
		hh.MerkleizeWithMixin(hashIndex, 0, ssz.CalculateLimit(listLimit, 0, elemType.Size()))
	} else {
		// For composite types, use the list limit directly
		hh.MerkleizeWithMixin(hashIndex, 0, listLimit)
	}
	return nil
}

// buildRootFromBasicList handles hash tree root computation for lists of basic types.
func buildRootFromBasicList(hashIndex int, listLimit, listLength, elemSize uint64, serializedData []byte, requiredDataSize uint64, hh *ssz.Hasher) error {
	// mix_in_length(merkleize(pack(value), limit=chunk_count(type)), len(value)) if value is a list of basic objects.
	hh.Append(serializedData[:requiredDataSize])

	// For basic types, calculate the maximum number of chunks based on element size
	chunkLimit := ssz.CalculateLimit(listLimit, listLength, elemSize)
	hh.MerkleizeWithMixin(hashIndex, listLength, chunkLimit)
	return nil
}

// buildRootFromCompositeList handles hash tree root computation for lists of composite types.
func buildRootFromCompositeList(hashIndex int, listLimit, listLength, elemSize uint64, elemType *sszquery.SSZInfo, elemTypeValue sszquery.SSZType, serializedData []byte, hh *ssz.Hasher) error {
	// mix_in_length(merkleize([hash_tree_root(element) for element in value], limit=chunk_count(type)), len(value)) if value is a list of composite objects.
	// For composite types, hash each element individually, then merkleize with length mixing
	for i := uint64(0); i < listLength; i++ {
		elementOffset := i * elemSize
		elementData := serializedData[elementOffset : elementOffset+elemSize]

		err := buildRootFromSSZInfo(elemType, elementData, hh)
		if err != nil {
			return fmt.Errorf("buildRootFromCompositeList: failed to hash list element %d of type %s: %w", i, elemTypeValue, err)
		}
	}

	// For composite types, each element becomes one chunk after hashing
	hh.MerkleizeWithMixin(hashIndex, listLength, listLimit)
	return nil
}

// buildRootFromCompatibleUnion computes the hash tree root for CompatibleUnion values.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error indicating that Union types are not yet implemented.
func buildRootFromCompatibleUnion(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	return fmt.Errorf("buildRootFromCompatibleUnion: Union type hash tree root computation is not yet implemented for type %s", si.Type())
}

// buildRootFromContainer computes the hash tree root for ssz containers.
//
// Parameters:
// - si: The SSZInfo describing the structure of the data.
// - serializedData: The SSZ-serialized byte slice of the object to compute the hash tree root for.
// - hh: The hasher instance to use for computing the hash tree root.
// Returns:
// - error if any issues occur during computation.
func buildRootFromContainer(si *sszquery.SSZInfo, serializedData []byte, hh *ssz.Hasher) error {
	hashIndex := hh.Index()

	if si.Type() != sszquery.Container {
		return fmt.Errorf("buildRootFromContainer: expected Container type, got %s", si.Type())
	}

	ci, err := si.ContainerInfo()
	if err != nil {
		return fmt.Errorf("buildRootFromContainer: failed to get container info: %w", err)
	}

	fieldOrder := ci.Order()
	if len(fieldOrder) == 0 {
		// Empty container - still needs merkleization
		hh.Merkleize(hashIndex)
		return nil
	}

	fields := ci.Fields()
	for _, fieldName := range fieldOrder {
		fieldInfo, ok := fields[fieldName]
		if !ok {
			return fmt.Errorf("buildRootFromContainer: field %s not found in container fields, available fields: %v", fieldName, getFieldNames(fields))
		}

		fieldType := fieldInfo.SSZ()
		if fieldType == nil {
			return fmt.Errorf("buildRootFromContainer: field %s has nil SSZInfo", fieldName)
		}

		fieldOffset := fieldInfo.Offset()
		fieldSize := fieldType.Size()

		// Validate field bounds
		if fieldOffset > uint64(len(serializedData)) {
			return fmt.Errorf("buildRootFromContainer: field %s offset %d exceeds data length %d", fieldName, fieldOffset, len(serializedData))
		}

		fieldEndOffset := fieldOffset + fieldSize
		if fieldEndOffset > uint64(len(serializedData)) {
			return fmt.Errorf("buildRootFromContainer: field %s (offset: %d, size: %d) exceeds data bounds, need %d bytes but have %d bytes", fieldName, fieldOffset, fieldSize, fieldEndOffset, len(serializedData))
		}

		err := buildRootFromSSZInfo(fieldType, serializedData[fieldOffset:fieldEndOffset], hh)
		if err != nil {
			return fmt.Errorf("buildRootFromContainer: failed to hash container field %s of type %s: %w", fieldName, fieldType.Type(), err)
		}
	}

	hh.Merkleize(hashIndex)
	return nil
}

// getFieldNames extracts field names from a field map for error reporting
func getFieldNames(fields map[string]*sszquery.FieldInfo) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	return names
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
