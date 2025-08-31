package query

// containerInfo maps a field's JSON name to its sszInfo for nested Containers.
type containerInfo = map[string]*fieldInfo

type fieldInfo struct {
	// sszInfo contains the SSZ information of the field.
	sszInfo *sszInfo
	// offset is the offset of the field within the parent struct.
	offset uint64
}

// Exported alias (or type) for container field map.
type ContainerInfo = containerInfo

// Exported FieldInfo with accessors
type FieldInfo = fieldInfo

// Exported fields
func (f *FieldInfo) SSZ() *SSZInfo {
	return f.sszInfo
}

func (f *FieldInfo) Offset() uint64 {
	return f.offset
}

func (f *FieldInfo) ActualOffset() uint64 {
	return f.offset
}
