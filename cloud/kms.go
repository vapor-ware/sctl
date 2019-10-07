package cloud

import (
	"context"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// KMS is a contract interface that must be implemented for sctl to talk to the backing KMS service's
// two methods of Encrypt and Decrypt, that return byte slices of plaintext/cyphertext respectively and
// any unwrapped errors that surface from the operation.
type KMS interface {
	Encrypt(string, []byte) ([]byte, error)
	Decrypt(string, []byte) ([]byte, error)
}

// GCPKMS is a Google Cloud Platform KMS client
// A wrapper for configuring gcloud, and consuming
// their KMS service for encrypt/decrypt and key management/acls
type GCPKMS struct {
	// property keyname - the URI to the GCP KMS keyring/key
	// eg: projects/sctl/locations/us/keyRings/sctl/cryptoKeys/sctl-dev

	keyname string
}

// Encrypt invokes GCP KMS to encrypt the data. Returns a bytestream of binary data.
func (gkms *GCPKMS) Encrypt(plaintext []byte) ([]byte, error) {
	// https://cloud.google.com/kms/docs/encrypt-decrypt#kms-howto-encrypt-go
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.EncryptRequest{
		Name:      gkms.keyname,
		Plaintext: plaintext,
	}
	// Call the API.
	resp, err := client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

// Decrypt invokes the GCP KMS API to decrypt ciphertext.
func (gkms *GCPKMS) Decrypt(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       gkms.keyname,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		// if this fails, it's likely network or permissions related
		return nil, err
	}

	// return the decrypted data, and the error object
	return resp.Plaintext, nil
}

// NewGCPKMS creates a new KMS client for Google Cloud Platform.
func NewGCPKMS(keyname string) GCPKMS {
	return GCPKMS{
		keyname: keyname,
	}
}
