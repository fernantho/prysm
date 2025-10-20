package query

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PathElement represents a single element in a path.
type PathElement struct {
	Length bool
	Name   string
	// [Optional] Index for List/Vector elements
	Index *uint64
}

func ParsePath(rawPath string) ([]PathElement, error) {
	// We use dot notation, so we split the path by '.'.
	rawElements := strings.Split(rawPath, ".")
	if len(rawElements) == 0 {
		return nil, errors.New("empty path provided")
	}

	if rawElements[0] == "" {
		// Remove leading dot if present
		rawElements = rawElements[1:]
	}

	var path []PathElement
	for _, elem := range rawElements {
		if elem == "" {
			return nil, errors.New("invalid path: consecutive dots or trailing dot")
		}

		fieldName := elem
		var index *uint64

		// Check for index notation, e.g., "field[0]"
		if strings.Contains(elem, "[") {
			parts := strings.SplitN(elem, "[", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid index notation in path element %s", elem)
			}

			fieldName = parts[0]
			indexPart := strings.TrimSuffix(parts[1], "]")
			if indexPart == "" {
				return nil, errors.New("index cannot be empty")
			}

			indexValue, err := strconv.ParseUint(indexPart, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid index in path element %s: %w", elem, err)
			}
			index = &indexValue
		}

		path = append(path, PathElement{Name: fieldName, Index: index})
	}

	return path, nil
}

// processPathElement processes a path element string and returns a PathElement struct
func processPathElement(elementStr string) (PathElement, error) {
	element := PathElement{}

	// Processing element string
	processingField := elementStr

	re := regexp.MustCompile(`^\s*len\s*\(\s*([^)]+?)\s*\)\s*$`)
	matches := re.FindStringSubmatch(processingField)
	if len(matches) == 2 {
		element.Length = true
		// Extract the inner expression between len( and ) and continue parsing on that
		processingField = matches[1]
	}

	// Default name is the full working string (may be updated below if it contains indices)
	element.Name = processingField

	if strings.Contains(processingField, "[") {
		// Split into field and indices, e.g., "array[0][1]" -> name:"array", indices:{0,1}
		element.Name = extractFieldName(processingField)
		indices, err := extractArrayIndices(processingField)
		if err != nil {
			return PathElement{}, err
		}
		element.Index = &indices[0] // For now, only support single index
	}

	return element, nil
}

// extractFieldName extracts the field name from a path element name (removes array indices)
// For example: "field_name[5]" returns "field_name"
func extractFieldName(name string) string {
	if idx := strings.Index(name, "["); idx != -1 {
		return name[:idx]
	}
	return strings.ToLower(name)
}

// extractArrayIndices returns every bracketed, non-negative index in the name,
// e.g. "array[0][1]" -> []uint64{0, 1}. Errors if none are found or if any index is invalid.
func extractArrayIndices(name string) ([]uint64, error) {
	// Match all bracketed content, then we'll parse as unsigned to catch negatives explicitly
	re := regexp.MustCompile(`\[\s*([^\]]+)\s*\]`)
	matches := re.FindAllStringSubmatch(name, -1)

	if len(matches) == 0 {
		return nil, errors.New("no array indices found")
	}

	indices := make([]uint64, 0, len(matches))
	for _, m := range matches {
		raw := strings.TrimSpace(m[1])
		// Forbid signs explicitly; we want a clear error similar to ParseUint's message
		if strings.HasPrefix(raw, "-") {
			return nil, fmt.Errorf("cannot process negative indices %q", raw)
		}
		idx, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid array index: %w", err)
		}
		indices = append(indices, idx)
	}
	return indices, nil
}
