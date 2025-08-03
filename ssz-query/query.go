package sszquery

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	sszMaxTag  = "ssz-max" // Used for variable-sized types like List and Bitlist.
	sszSizeTag = "ssz-size"
)

func PreCalculateSSZInfo(obj any) (*sszInfo, error) {
	// Get the value of the object using reflection.
	currentValue := reflect.ValueOf(obj)
	if currentValue.Kind() == reflect.Ptr {
		if currentValue.IsNil() {
			// If we encounter a nil pointer before the end of the path, we can still proceed
			// by analyzing the type, not the value.
			currentValue = reflect.New(currentValue.Type().Elem()).Elem()
		} else {
			currentValue = currentValue.Elem()
		}
	}

	info, err := analyzeType(currentValue.Type(), nil)
	if err != nil {
		return nil, fmt.Errorf("analyze type %s: %w", currentValue.Type().Name(), err)
	}

	return info, nil
}

func CalculateOffsetAndLength(sszInfo *sszInfo, path []PathElement) (uint64, uint64, error) {
	if sszInfo == nil {
		return 0, 0, fmt.Errorf("sszInfo is nil")
	}

	if len(path) == 0 {
		return 0, 0, fmt.Errorf("path is empty")
	}

	walk := sszInfo
	currentOffset := uint64(0)

	for _, elem := range path {
		offset, exists := walk.fieldOffsets[elem.Name]
		if !exists {
			// TODO: This logic is only for accessing the field in SSZ container types.
			return 0, 0, fmt.Errorf("field %s not found in fieldOffsets", elem.Name)
		}

		currentOffset += offset
		walk, exists = walk.fieldInfos[elem.Name]
		if !exists {
			// TODO: Same as above.
			return 0, 0, fmt.Errorf("field %s not found in fieldInfos", elem.Name)
		}
	}

	return currentOffset, walk.FixedSize(), nil
}

// analyzeType is an entry point that inspects a reflect.Type and computes its SSZ layout information.
func analyzeType(typ reflect.Type, tag *reflect.StructTag) (*sszInfo, error) {
	switch typ.Kind() {
	// Basic types (e.g., uintN where N is 8, 16, 32, 64)
	// NOTE: uint128 and uint256 are represented as []byte in Go,
	// so we handle them as slices.
	case reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Bool:
		return analyzeBasicType(typ)
	case reflect.Slice, reflect.Array:
		elemType := typ.Elem()
		// Special handling for byte slices.
		// e.g., Root (Bytes32), Signature (Bytes96)
		// e.g2., uint128 ([]bytes with length 16) and uint256 ([]byte with length 32).
		if elemType.Kind() == reflect.Uint8 {
			sszSize := tag.Get(sszSizeTag)
			if sszSize == "" {
				return nil, fmt.Errorf("ssz-size tag is required for byte slices")
			}

			byteLength, err := strconv.Atoi(sszSize)
			if err != nil {
				return nil, fmt.Errorf("invalid ssz-size tag for byte slice: %w",
					err)
			}

			return &sszInfo{
				// `BytesN` type is an alias of `Vector[byte, N]`, so we use Vector type.
				// TODO: How can we distinguish between `BytesN` and `uint{128,256}`?
				sszType: Vector,

				fixedSize:  uint64(byteLength),
				isVariable: false,
			}, nil
		}

		return analyzeHomogeneousColType(typ, tag)
	case reflect.Struct:
		return analyzeContainerType(typ)
	case reflect.Ptr:
		// Dereference pointer types.
		return analyzeType(typ.Elem(), tag)
	default:
		return nil, fmt.Errorf("unsupported type for SSZ calculation: %v", typ.Kind())
	}
}

// analyzeBasicType analyzes SSZ basic types (uintN, bool) and returns its info.
func analyzeBasicType(typ reflect.Type) (*sszInfo, error) {
	sszInfo := &sszInfo{
		// Every basic type is fixed-size and not variable.
		isVariable: false,
	}

	switch typ.Kind() {
	case reflect.Uint64:
		sszInfo.sszType = UintN
		sszInfo.fixedSize = 8
		return sszInfo, nil
	case reflect.Uint32:
		sszInfo.sszType = UintN
		sszInfo.fixedSize = 4
		return sszInfo, nil
	case reflect.Uint16:
		sszInfo.sszType = UintN
		sszInfo.fixedSize = 2
		return sszInfo, nil
	case reflect.Uint8:
		sszInfo.sszType = UintN
		sszInfo.fixedSize = 1
		return sszInfo, nil
	case reflect.Bool:
		sszInfo.sszType = Boolean
		sszInfo.fixedSize = 1
		return sszInfo, nil
	default:
		return nil, fmt.Errorf("unsupported basic type for SSZ calculation: %v", typ.Kind())
	}
}

// analyzeContainerType analyzes SSZ Container type and returns its SSZ info.
func analyzeContainerType(typ reflect.Type) (*sszInfo, error) {
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("can only analyze struct types, got %v", typ.Kind())
	}

	sszInfo := &sszInfo{
		sszType: Container,

		fieldOffsets: make(map[string]uint64),
		goFieldNames: make(map[string]string),
		fieldInfos:   make(map[string]*sszInfo),
	}
	var currentOffset uint64
	var structIsVariable bool

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// Protobuf-generated structs contain private fields we must skip.
		// e.g., state, sizeCache, unknownFields, etc.
		if !field.IsExported() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" {
			// If the field has no JSON tag, we skip it.
			continue
		}

		// The JSON tag contains the field name in the first part.
		// e.g., "attesting_indices,omitempty" -> "attesting_indices".
		// NOTE: `fieldName` is a string with snake_case format (following consensus specs).
		fieldName := strings.Split(jsonTag, ",")[0]
		if fieldName == "" {
			continue
		}

		// Analyze each field so that we can complete full SSZ information.
		info, err := analyzeType(field.Type, &field.Tag)
		if err != nil {
			return nil, fmt.Errorf("analyze type for field %s: %w", fieldName, err)
		}

		// If one of the fields is variable-sized,
		// the entire struct is considered variable-sized.
		if info.isVariable {
			structIsVariable = true
		}

		sszInfo.fieldOffsets[fieldName] = currentOffset
		sszInfo.goFieldNames[fieldName] = field.Name
		// Store nested struct info.
		sszInfo.fieldInfos[fieldName] = info

		// Update the current offset based on the field's fixed size.
		currentOffset += info.fixedSize
	}

	sszInfo.fixedSize = currentOffset
	sszInfo.isVariable = structIsVariable
	return sszInfo, nil
}

// analyzeHomogeneousColType analyzes homogeneous collection types (e.g., List, Vector, Bitlist, Bitvector) and returns its SSZ info.
// TODO: We need to contain the element type.
func analyzeHomogeneousColType(typ reflect.Type, tag *reflect.StructTag) (*sszInfo, error) {
	if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Array {
		return nil, fmt.Errorf("can only analyze slice/array types, got %v", typ.Kind())
	}

	if tag == nil {
		return nil, fmt.Errorf("tag is required for slice/array types")
	}

	// Prioritize ssz-max tag if present.
	// ssz-max is only used for variable sized types like List and Bitlist.
	sszMax := tag.Get(sszMaxTag)
	if sszMax != "" {
		return &sszInfo{
			// TODO: How do we distinguish between List and Bitlist?
			sszType: List,

			fixedSize:  4,
			isVariable: true,
		}, nil
	}

	sszSize := tag.Get(sszSizeTag)
	dims := strings.Split(sszSize, ",")
	sizeVal, err := strconv.Atoi(dims[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ssz-size tag on field: %w", err)
	}

	return &sszInfo{
		// TODO: How do we distinguish between Vector and List?
		sszType: Vector,

		fixedSize:  uint64(sizeVal),
		isVariable: false,
	}, nil
}
