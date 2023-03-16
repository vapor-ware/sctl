package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ErrConfigLoad is a struct fulfilling the error interface. It specified errors
// where sctl failed to load its config, which is useful to know, since this could
// be the case on first-run.
type ErrConfigLoad struct{}

func (e *ErrConfigLoad) Error() string {
	return "failed to load sctl configuration"
}

// Configuration objects wrap the $UserConfig object we store so we can identify which cloud credentials we
// have, as well as the known client configuration for our clouds. Unfortunately for google users, we
// cannot distribute API keys as part of our open source application. This necessitates every sctl admin
// to create a GCP project, and issue a client credential for authenticating users.
// We will need these values throughout the lifetime of credential issuance so we'll serialize these
// not secret, but EULA bound credentials in the persistent configuration.

// A documented model of the proposed configuration is as follows
// Note the prefix of GCP on the cloud options. The intent is to namespace
// so in the future adding additional clouds will not be disruptive to the structure of sctl.
//
//
// {
//    // client is responsible for recording the base64 encoded application client credentials.
// these API keys only identify the requesting application, and broker the authentication
// between operator and GCP
//     "gcp_client_config": {
//         "data": "BASE64 Data",
//     }
// }

// Configuration warehouses the sctl user configuration. Details that are not secrets
// but don't belong in secret state.
// params:
// GoogleClient identifies the sctl application when being used in the OAUTH2 login flow.
// configPath is the path to store sctl's configuration
// configFilePath is the path to sctl's config.json
type Configuration struct {
	GoogleClient   Client `json:"gcp_client_config,omitempty"`
	configPath     string
	configFilePath string
}

// Client is a sub-object warehousing the client configuration data
// provided by google. https://console.developers.google.com/
type Client struct {
	Data string `json:"data,omitempty"`
}

// Save Serializes the configuration to json and stores it on disk in
// the operating systems configuration path.
func (c *Configuration) Save() error {
	jsonData, err := json.MarshalIndent(&c, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.configFilePath, jsonData, os.FileMode(0600))
}

// Load will load the json from disk and populate the configuration with
// values restored from the configuration
func (c *Configuration) Load() error {
	f, err := os.ReadFile(c.configFilePath)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(f), c)
}

// Init will generate the configuration path for sctl in the system UserConfigDir
func (c *Configuration) Init() error {
	if c.configPath == "" {
		return nil
	}
	return os.MkdirAll(c.configPath, 0775)
}

// ReadConfiguration will instantiate a Configuration struct and attempt to load from
// the serialized data. If an error is encountered processing this operation
// a blank Configuration struct will be returned.
func ReadConfiguration() (Configuration, error) {
	c := Configuration{}
	if err := c.Init(); err != nil {
		return c, err
	}

	osConfigDir, _ := os.UserConfigDir()
	c.configPath = filepath.FromSlash(osConfigDir + "/sctl")
	c.configFilePath = filepath.FromSlash(c.configPath + "/config.json")
	if err := c.Load(); err != nil {
		return c, &ErrConfigLoad{}
	}
	// If this errors, we still want the empty Configuration object.
	// This will account/allow first run usage, but may mask errors later.
	// Handling this case is TODO
	return c, nil
}

// IsConfigLoadErr is a helper function which checks if a given error is an instance
// of the ErrConfigLoad error.
func IsConfigLoadErr(err error) bool {
	_, ok := err.(*ErrConfigLoad)
	return ok
}
