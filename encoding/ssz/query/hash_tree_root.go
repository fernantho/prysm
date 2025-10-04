package query

import (
	"errors"
)

// HashTreeRoot calls the HashTreeRoot method on the stored value if it implements the Hashable interface.
// This leverages the SSZ-generated HashTreeRoot methods from Fastssz.
func (info *sszInfo) HashTreeRoot() ([32]byte, error) {
	if info == nil {
		return [32]byte{}, errors.New("sszInfo is nil")
	}

	if info.iface == nil {
		return [32]byte{}, errors.New("not stored iface")
	}

	// Check if the value implements the Hashable interface
	if hashable, ok := info.iface.(interface{ HashTreeRoot() ([32]byte, error) }); ok {
		return hashable.HashTreeRoot()
	}

	return [32]byte{}, errors.New("stored interface does not implement HashTreeRoot() method")
}
