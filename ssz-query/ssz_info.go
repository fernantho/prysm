package sszquery

import (
	"fmt"
	"sort"
	"strings"
)

// sszInfo holds the pre-calculated SSZ data for a struct type.
type sszInfo struct {
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

func (info *sszInfo) Print() string {
	if info == nil {
		return "<nil>"
	}
	var builder strings.Builder
	printRecursive(info, &builder, "")
	return builder.String()
}

func printRecursive(info *sszInfo, builder *strings.Builder, prefix string) {
	builder.WriteString(fmt.Sprintf("Struct (fixedSize: %d, isVariable: %t)\n", info.fixedSize, info.isVariable))

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
