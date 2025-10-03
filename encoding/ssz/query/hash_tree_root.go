package query

import (
	"errors"
	"fmt"
)

// HashTreeRoot calls the HashTreeRoot method on the stored value if it implements the Hashable interface.
// This leverages the SSZ-generated HashTreeRoot methods from Fastssz.
func (info *sszInfo) HashTreeRoot() ([32]byte, error) {
	if info == nil {
		return [32]byte{}, errors.New("sszInfo is nil")
	}

	if info.value == nil {
		return [32]byte{}, errors.New("stored value is nil")
	}

	// Check if the value implements the Hashable interface
	if hashable, ok := info.value.(interface{ HashTreeRoot() ([32]byte, error) }); ok {
		return hashable.HashTreeRoot()
	}

	return [32]byte{}, fmt.Errorf("stored value of type %T does not implement HashTreeRoot() method", info.value)
}
