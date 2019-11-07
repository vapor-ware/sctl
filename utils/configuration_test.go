package utils

import (
	"path/filepath"
	"testing"
)

func TestLoadGoodConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_good_config.json")
	c.Load()

	if len(c.GoogleClient.Data) <= 1 {
		t.Errorf("Unexpected empty client JSON. Wanted: >1 Got:  %v", len(c.GoogleClient.Data))
	}

}

func TestLoadBadConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_bad_config.json")
	c.Load()

	if len(c.GoogleClient.Data) != 0 {
		t.Errorf("Unexpected empty client JSON. Wanted: 0 Got:  %v", len(c.GoogleClient.Data))
	}

}

func TestLoadMissingConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/non_existant.json")
	err := c.Load()

	if err == nil {
		t.Errorf("Unexpected success. Wanted: FileNotFound Error, Got: nil")
	}

}
func TestConfigInit(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.Init()
}

func TestSaveConfig(t *testing.T) {
	c := Configuration{}
	c.configPath = filepath.FromSlash("../testdata")
	c.configFilePath = filepath.FromSlash(c.configPath + "/test_save_config.json")

	c.Save()

}

func TestReacConfiguration(t *testing.T) {
	c := ReadConfiguration()

	if len(c.configPath) == 0 {
		t.Errorf("Unexpected missing ConfigPath. Wanted: not-nil Got: nil")
	}
}
