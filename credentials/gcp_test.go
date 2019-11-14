package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

func TestKeyringMock(t *testing.T) {
	gc := GoogleCredential{}
	keyring.MockInit()

	err := gc.SaveCredential("test", GoogleToken{ClientID: "test",
		ClientSecret: "test",
		RefreshToken: "test",
		TheType:      "test_user"})
	if err != nil {
		t.Errorf("Unexpected error during SaveCredential: %v", err)
	}

	cred, err := gc.GetCredential("test")
	if err != nil {
		t.Fatal("Unexpected error during GetCredential")
	}

	if cred.ClientID != "test" {
		t.Errorf("Unexpected ClientID value. Wanted: test  Got: %v", cred.ClientID)
	}
	if cred.ClientSecret != "test" {
		t.Errorf("Unexpected ClientSecret value. Wanted: test  Got: %v", cred.ClientSecret)
	}
	if cred.RefreshToken != "test" {
		t.Errorf("Unexpected RefreshToken value. Wanted: test  Got: %v", cred.RefreshToken)
	}
	if cred.TheType != "test_user" {
		t.Errorf("Unexpected Type value. Wanted: test_user Got: %v", cred.TheType)
	}

	err = gc.DeleteCredential("test")
	if err != nil {
		t.Errorf("Unexpected error removing credential: %v", err)
	}
}

func TestKeyringMissingCredential(t *testing.T) {
	gc := GoogleCredential{}
	keyring.MockInit()

	_, err := gc.GetCredential("nonexistant")

	if err == nil {
		t.Errorf("Unexpected success. %v", err)
	}
}

func TestValidateContext(t *testing.T) {
	gc := GoogleCredential{}

	gap, exists := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	if exists {
		err := gc.ValidateContext()
		if err == nil {
			t.Errorf("Unexpected success. Wanted: GOOGLE_APPLICATION_CREDENTIALS warning Got: nil,")
		}
		_ = os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	noerr := gc.ValidateContext()
	if noerr != nil {
		t.Errorf("Unexpected error. Wanted: nil warning Got: %v", noerr)
	}

	if exists {
		_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", gap)
	}
}

func TestFormatCredential(t *testing.T) {
	clientJSON := `{"installed":{"client_id":"someclient.apps.googleusercontent.com","project_id":"scuttle","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"asecret","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}`

	gc := GoogleCredential{}
	token := oauth2.Token{AccessToken: "test",
		RefreshToken: "test",
		TokenType:    "test_token"}

	cred, err := gc.formatCredential(&token, []byte(clientJSON))
	if err != nil {
		t.Fatalf("Unexpected error formatting credential: %v", err)
	}

	if cred.ClientID != "someclient.apps.googleusercontent.com" {
		t.Errorf("Unexpected ClientID value. Wanted: someclient.apps.googleusercontent.com  Got: %v", cred.ClientID)
	}

	if cred.ClientSecret != "asecret" {
		t.Errorf("Unexpected ClientSecret value. Wanted: asecret  Got: %v", cred.ClientSecret)
	}

	if cred.RefreshToken != "test" {
		t.Errorf("Unexpected RefreshToken value. Wanted: test  Got: %v", cred.RefreshToken)
	}

	if cred.TheType != "authorized_user" {
		t.Errorf("Unexpected Type value. Wanted: authorized_user  Got: %v", cred.TheType)
	}
}

func TestJSONFromKeyring(t *testing.T) {
	gc := GoogleCredential{}
	_, isExist := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")

	if isExist {
		t.Skip("Detected GOOGLE_APPLICATION_CREDENTIALS override")
	}
	keyring.MockInit()
	err := keyring.Set("scuttle", "default-gcp", "{\"client_id\":\"test.apps.googleusercontent.com\",\"client_secret\":\"ITSASECRET\",\"refresh_token\":\"Refreshing\",\"type\":\"authorized_user\"}")
	if err != nil {
		t.Errorf("Unexpected error for keyring.Set: %v", err)
	}

	keyJSON, err := gc.JSON()
	if err != nil {
		t.Errorf("Unexpected error for gc.JSON: %v", err)
	}
	if len(keyJSON) == 0 {
		t.Errorf("Unexpected zero-byte return. Wanted: []byte respresentation of GoogleToken. Got: []byte{}")
	}
}

func TestJSONFromKeyringBadCred(t *testing.T) {
	gc := GoogleCredential{}
	_, isExist := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")

	if isExist {
		t.Skip("Detected GOOGLE_APPLICATION_CREDENTIALS override")
	}
	keyring.MockInit()

	_, err := gc.JSON()

	if err == nil {
		t.Error("Unexpected success. Wanted: FileNotFound error, got: nil")
	}
}

func TestJSONFromEnv(t *testing.T) {
	err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.FromSlash("../testdata/test_google_token.json"))
	if err != nil {
		t.Fatalf("failed to set test environment: %v", err)
	}

	gc := GoogleCredential{}
	keyJSON, err := gc.JSON()
	if err != nil {
		t.Errorf("Unexpected error from gc.JSON: %v", err)
	}

	if len(keyJSON) == 0 {
		t.Errorf("Unexpected zero-byte return.  Wanted: []byte respresentation of GoogleToken. Got: []byte{}")
	}
}

func TestJSONErrorFromEnv(t *testing.T) {
	err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.FromSlash("../testdata/nonexistant.json"))
	if err != nil {
		t.Fatalf("failed to set test environment: %v", err)
	}

	gc := GoogleCredential{}
	_, err = gc.JSON()

	if err == nil {
		t.Error("Unexected success. Wanted: FileNotFound error, got: nil")
	}
}
