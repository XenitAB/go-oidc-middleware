package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpaqueOptions(t *testing.T) {
	expectedResult := &OpaqueOptions{}
	setters := []OpaqueOption{}

	result := &OpaqueOptions{}

	for _, setter := range setters {
		setter(result)
	}

	require.Equal(t, expectedResult, result)
}
