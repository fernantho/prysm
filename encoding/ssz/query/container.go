package query

// containerInfo has
// 1. fields: a field map that maps a field's JSON name to its SszInfo for nested Containers
// 2. order: a list of field names in the order they should be serialized
// 3. fixedOffset: the total size of the fixed part of the container
type containerInfo struct {
	fields      map[string]*fieldInfo
	order       []string
	fixedOffset uint64
}

// Fields returns the field map of the container.
func (ci *containerInfo) Fields() map[string]*fieldInfo {
	if ci == nil {
		return nil
	}

	return ci.fields
}

type fieldInfo struct {
	// sszInfo contains the SSZ information of the field.
	sszInfo *SszInfo
	// offset is the offset of the field within the parent struct.
	offset uint64
	// goFieldName is the name of the field in Go struct.
	goFieldName string
}

// SszInfo returns the SszInfo of the field.
func (fi *fieldInfo) SszInfo() *SszInfo {
	if fi == nil {
		return nil
	}

	return fi.sszInfo
}
