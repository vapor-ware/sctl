package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadGoodConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_good_config.json")
	err := c.Load()

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(c.GoogleClient.Data), 1)
}

func TestLoadBadConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_bad_config.json")
	err := c.Load()

	assert.NoError(t, err)
	assert.Len(t, c.GoogleClient.Data, 0)
}

func TestLoadMissingConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/non_existant.json")
	err := c.Load()

	assert.Error(t, err)
}

func TestConfigInit(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	err := c.Init()

	assert.NoError(t, err)
}

func TestSaveConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_save_config.json")

	err := c.Save()
	assert.NoError(t, err)
}

func TestReadConfiguration(t *testing.T) {
	c, err := ReadConfiguration()
	if err != nil {
		assert.True(t, IsConfigLoadErr(err))
	}
	assert.NotEmpty(t, c.configPath)
}
