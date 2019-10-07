// +build !unit

package cloud

import (
	"os"
	"reflect"
	"testing"
)

const defaultTestKey = "projects/vapor-staging/locations/us/keyRings/sctl/cryptoKeys/sctl-dev"

// Determine if the env is configured, if not, these tests
// should be skipped.
func validateTestEnv(t *testing.T) {
	if len(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")) == 0 {
		t.Skip("Skipping - Missing ENV GOOGLE_APPLICATION_CREDENTIALS")
	}
	if len(os.Getenv("SCTL_KEY")) == 0 {
		t.Skip("Skipping - Missing ENV SCTL_KEY")
	}
}

// Expensive KMS testing that actually invokes the KMS API. In order for these integration tests
// to pass you must have the environment variable GOOGLE_APPLICATION_CREDENTIALS configured, and
// the actor of those credentials must be able to access the KMS key declared.
func TestGCPKMSEncryptDecryptIntegration(t *testing.T) {
	validateTestEnv(t)
	client := NewGCPKMS(os.Getenv("SCTL_KEY"))
	cypher, err := client.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Unexpected error. Wanted: nil Got: %s", err)
	}

	decrypted, err := client.Decrypt(cypher)

	if err != nil {
		t.Fatalf("Unexpected error. Wanted: nil Got: %s", err)
	}

	if reflect.DeepEqual(decrypted, []byte("hello")) != true {
		t.Fatalf("Unexpected value. Wanted: hello Got: %s", err)
	}

}
