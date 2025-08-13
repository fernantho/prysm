package query

import (
	"reflect"
)

// sszInfo holds the all necessary data for analyzing SSZ data types.
type sszInfo struct {
	// Type of the SSZ structure (Basic, Container, List, etc.).
	sszType SSZType
	// Type in Go. Need this for unmarshaling.
	typ reflect.Type

	// isVariable is true if the struct contains any variable-size fields.
	isVariable bool
	// fixedSize is the total size of the struct's fixed part.
	fixedSize uint64
}

func (info *sszInfo) FixedSize() uint64 {
	if info == nil {
		return 0
	}
	return info.fixedSize
}

func (info *sszInfo) Size() uint64 {
	if info == nil {
		return 0
	}

	// Easy case: if the type is not variable, we can return the fixed size.
	if !info.isVariable {
		return info.fixedSize
	}

	// TODO: Handle variable-sized types.
	return 0
}
