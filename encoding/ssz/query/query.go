package query

import (
	"errors"
	"fmt"
)

// CalculateOffsetAndLength calculates the offset and length of a given path within the SSZ object.
// By walking the given path, it accumulates the offsets based on sszInfo.
func CalculateOffsetAndLength(sszInfo *sszInfo, path []PathElement) (*sszInfo, uint64, uint64, error) {
	if sszInfo == nil {
		return nil, 0, 0, errors.New("sszInfo is nil")
	}

	if len(path) == 0 {
		return nil, 0, 0, errors.New("path is empty")
	}

	walk := sszInfo
	offset := uint64(0)

	for pathIndex, elem := range path {
		containerInfo, err := walk.ContainerInfo()
		if err != nil {
			return nil, 0, 0, fmt.Errorf("could not get field infos: %w", err)
		}

		fieldInfo, exists := containerInfo.fields[elem.Name]
		if !exists {
			return nil, 0, 0, fmt.Errorf("field %s not found in containerInfo", elem.Name)
		}

		offset += fieldInfo.offset
		walk = fieldInfo.sszInfo

		// Check for accessing List/Vector elements by index
		if elem.Index != nil {
			switch walk.sszType {
			case List:
				index := *elem.Index
				listInfo := walk.listInfo
				if index >= listInfo.length {
					return nil, 0, 0, fmt.Errorf("index %d out of bounds for field %s", index, elem.Name)
				}

				walk = listInfo.element
				if walk.isVariable {
					// Cumulative sum of sizes of previous elements to get the offset.
					for i := range index {
						offset += listInfo.elementSizes[i]
					}

					// IMPORTANT: For variable-sized lists, we must use the stored element size at this index
					// rather than the element template's size. When populating variable-length info, the shared
					// element template is recursively updated for each list item, causing it to retain the
					// size information of the last processed element. The correct individual element sizes
					// are preserved in the elementSizes array.
					if pathIndex == len(path)-1 {
						return walk, offset, listInfo.elementSizes[index], nil
					}
				} else {
					offset += index * listInfo.element.Size()
				}

			case Vector:
				index := *elem.Index
				vectorInfo := walk.vectorInfo
				if index >= vectorInfo.length {
					return nil, 0, 0, fmt.Errorf("index %d out of bounds for field %s", index, elem.Name)
				}

				offset += index * vectorInfo.element.Size()
				walk = vectorInfo.element

			default:
				return nil, 0, 0, fmt.Errorf("field %s is not a List/Vector, cannot index", elem.Name)
			}
		}
	}

	return walk, offset, walk.Size(), nil
}
