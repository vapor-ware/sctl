package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

func TestKeyringMock(t *testing.T) {
	gc := GoogleCredential{}
	keyring.MockInit()

	err := gc.SaveCredential("test", GoogleToken{ClientID: "test",
		ClientSecret: "test",
		RefreshToken: "test",
		TheType:      "test_user",
	})
	assert.NoError(t, err)

	cred, err := gc.GetCredential("test")
	assert.NoError(t, err)
	assert.Equal(t, "test", cred.ClientID)
	assert.Equal(t, "test", cred.ClientSecret)
	assert.Equal(t, "test", cred.RefreshToken)
	assert.Equal(t, "test_user", cred.TheType)

	err = gc.DeleteCredential("test")
	assert.NoError(t, err)
}

func TestKeyringMissingCredential(t *testing.T) {
	gc := GoogleCredential{}
	keyring.MockInit()

	_, err := gc.GetCredential("nonexistant")
	assert.Error(t, err)
}

func TestValidateContext(t *testing.T) {
	gc := GoogleCredential{}

	gap, exists := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	if exists {
		err := gc.ValidateContext()
		assert.Error(t, err)
		_ = os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	noerr := gc.ValidateContext()
	assert.NoError(t, noerr)

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
	assert.NoError(t, err)
	assert.Equal(t, "someclient.apps.googleusercontent.com", cred.ClientID)
	assert.Equal(t, "asecret", cred.ClientSecret)
	assert.Equal(t, "test", cred.RefreshToken)
	assert.Equal(t, "authorized_user", cred.TheType)
}

func TestJSONFromKeyring(t *testing.T) {
	gc := GoogleCredential{}
	_, isExist := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	if isExist {
		t.Skip("Detected GOOGLE_APPLICATION_CREDENTIALS override")
	}

	keyring.MockInit()
	err := keyring.Set("scuttle", "default-gcp", "{\"client_id\":\"test.apps.googleusercontent.com\",\"client_secret\":\"ITSASECRET\",\"refresh_token\":\"Refreshing\",\"type\":\"authorized_user\"}")
	assert.NoError(t, err)

	keyJSON, err := gc.JSON()
	assert.NoError(t, err)
	assert.Greater(t, len(keyJSON), 0)
}

func TestJSONFromKeyringBadCred(t *testing.T) {
	gc := GoogleCredential{}
	_, isExist := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	if isExist {
		t.Skip("Detected GOOGLE_APPLICATION_CREDENTIALS override")
	}

	keyring.MockInit()

	_, err := gc.JSON()
	assert.Error(t, err)
}

func TestJSONFromEnv(t *testing.T) {
	err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.FromSlash("../testdata/test_google_token.json"))
	assert.NoError(t, err)

	gc := GoogleCredential{}
	keyJSON, err := gc.JSON()
	assert.NoError(t, err)
	assert.Greater(t, len(keyJSON), 0)
}

func TestJSONErrorFromEnv(t *testing.T) {
	err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.FromSlash("../testdata/nonexistant.json"))
	assert.NoError(t, err)

	gc := GoogleCredential{}
	_, err = gc.JSON()
	assert.Error(t, err)
}
