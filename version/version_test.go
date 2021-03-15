package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	v := GetVersion()

	assert.Equal(t, "", v.BuildDate)
	assert.Equal(t, "", v.Commit)
	assert.Equal(t, "", v.Tag)
	assert.Equal(t, "", v.Version)
	assert.NotEmpty(t, v.Arch)
	assert.NotEmpty(t, v.OS)
	assert.NotEmpty(t, v.Compiler)
}

func TestGetVersion2(t *testing.T) {
	Commit = "123"
	Tag = "tag-1"

	v := GetVersion()

	assert.Equal(t, "", v.BuildDate)
	assert.Equal(t, "123", v.Commit)
	assert.Equal(t, "tag-1", v.Tag)
	assert.Equal(t, "", v.Version)
	assert.NotEmpty(t, v.Arch)
	assert.NotEmpty(t, v.OS)
	assert.NotEmpty(t, v.Compiler)
}
