package sszquery

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	ssz "github.com/prysmaticlabs/fastssz"
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
// TODO: maybe we should another field for which type? (e.g., "Container", "List", etc.)
type sszInfo struct {
	// Type of the SSZ structure (Basic, Container, List).
	sszType SSZType
	typ     reflect.Type

	// isVariable is true if the struct contains any variable-size fields.
	isVariable bool
	// fixedSize is the total size of the struct's fixed part.
	fixedSize uint64

	// For structs, additional information is stored:
	//
	// fieldOffsets maps a field's JSON name to its offset within the struct's fixed part.
	fieldOffsets map[string]uint64
	// goFieldNames maps a field's JSON name to its Go struct field name (e.g., "attesting_indices" -> "AttestingIndices").
	// TODO: do we need this?
	goFieldNames map[string]string
	// fieldInfos maps a field's JSON name to its SSZ info (for nested structs).
	fieldInfos map[string]*sszInfo
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

	unmarshaler, ok := newObjPtr.Interface().(ssz.Unmarshaler)
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
	if info.sszType == Container {
		builder.WriteString(fmt.Sprintf("%s: %s (fixedSize: %d, isVariable: %t)\n", info.sszType, info.typ.Name(), info.fixedSize, info.isVariable))
	} else {
		builder.WriteString(fmt.Sprintf("%s (fixedSize: %d, isVariable: %t)\n", info.sszType, info.fixedSize, info.isVariable))
	}

	keys := make([]string, 0, len(info.fieldOffsets))
	for k := range info.fieldOffsets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, key := range keys {
		connector := "├─"
		nextPrefix := prefix + "│  "
		if i == len(keys)-1 {
			connector = "└─"
			nextPrefix = prefix + "   "
		}

		builder.WriteString(fmt.Sprintf("%s%s %s (offset: %d) ", prefix, connector, key, info.fieldOffsets[key]))

		if nestedInfo, ok := info.fieldInfos[key]; ok && nestedInfo != nil {
			printRecursive(nestedInfo, builder, nextPrefix)
		} else {
			builder.WriteString("\n")
		}
	}
}
