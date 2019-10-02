package cloud

import (
	"context"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// KMS -
type KMS interface {
	Encrypt(string, []byte) ([]byte, error)
	Decrypt(string, []byte) ([]byte, error)
}

// GCPKMS -
type GCPKMS struct{}

// Encrypt -
func (gkms GCPKMS) Encrypt(keyName string, plaintext []byte) ([]byte, error) {
	// https://cloud.google.com/kms/docs/encrypt-decrypt#kms-howto-encrypt-go
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.EncryptRequest{
		Name:      keyName,
		Plaintext: plaintext,
	}
	// Call the API.
	resp, err := client.Encrypt(ctx, req)
	return resp.Ciphertext, err
}

// Decrypt -
func (gkms GCPKMS) Decrypt(keyName string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		// if this fails, its likely network or permissions related
		return nil, err
	}

	// return the decrypted data, and the error object
	return resp.Plaintext, err
}

/* Note as of the time of import, I'm not sure how I would properly stub out the KMS key service.
   I'm going to leave these wrappers + the interface as a means to stub out and provide support
   for other KMS providers like AWS in a future release.

   TODO: Add integration tests, as unit tests are proving questionable.
*/

// encrypt will encrypt the input plaintext with the specified symmetric key
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func encryptSymmetric(keyName string, plaintext []byte, kmsClient KMS) ([]byte, error) {
	return kmsClient.Encrypt(keyName, plaintext)
}

// decrypt will decrypt the input ciphertext bytes using the specified symmetric key
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
func decryptSymmetric(keyName string, ciphertext []byte, kmsClient KMS) ([]byte, error) {
	return kmsClient.Decrypt(keyName, ciphertext)
}
