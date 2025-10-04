package query

type SSZIface interface {
	HashTreeRoot() ([32]byte, error)
	MarshalSSZ() ([]byte, error)
	UnmarshalSSZ([]byte) error
	// HashTreeRootWith(hh *ssz.Hasher) error
	// TODO check othes
}
