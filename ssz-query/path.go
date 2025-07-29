package sszquery

import (
	"fmt"
	"strings"
)

type PathElement struct {
	Name string
}

func ParsePath(rawPath string) ([]PathElement, error) {
	// We use Dot notation, so we split the path by '.'.
	rawElements := strings.Split(rawPath, ".")
	if len(rawElements) == 0 {
		return nil, fmt.Errorf("empty path provided")
	}

	if rawElements[0] == "" {
		rawElements = rawElements[1:] // Remove leading dot if present
	}

	var path []PathElement
	for _, elem := range rawElements {
		path = append(path, PathElement{Name: elem})
	}

	return path, nil
}
