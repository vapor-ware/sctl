// +build !unit

package cloud

import (
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

const defaultTestKey = "projects/vapor-staging/locations/us/keyRings/sctl/cryptoKeys/sctl-dev"

// Determine if the env is configured, if not, these tests
// should be skipped.
func validateTestEnv(t *testing.T) {
	if len(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")) == 0 {
		t.Skip("Skipping - Missing ENV GOOGLE_APPLICATION_CREDENTIALS")
	}
}

// Expensive KMS testing that actually invokes the KMS API. In order for these integration tests
// to pass you must have the environment variable GOOGLE_APPLICATION_CREDENTIALS configured, and
// the actor of those credentials must be able to access the KMS key declared.
func TestGCPKMSEncryptDecryptIntegration(t *testing.T) {
	validateTestEnv(t)
	key, found := os.LookupEnv("SCTL_KEY")

	var client KMS
	if found != true {
		client = NewGCPKMS(defaultTestKey)
	} else {
		client = NewGCPKMS(key)
	}

	cypher, err := client.Encrypt([]byte("hello"))
	assert.NoError(t, err)

	decrypted, err := client.Decrypt(cypher)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(decrypted, []byte("hello")))
}
