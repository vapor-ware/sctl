package credentials

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/pkg/errors"
	"github.com/vapor-ware/sctl/utils"
	"github.com/zalando/go-keyring"
)

// KeyNamespace is the application domain in which we will store credentials
// in the OS keyring
const KeyNamespace = "scuttle"

// CredentialVar is a reference to the google application credential env configuration path
// which can be used to short-circuit the credential provider storage and read directly from
// the provided credential.json
const CredentialVar = "GOOGLE_APPLICATION_CREDENTIALS"

// GoogleCredential represents the workflow needed to attain a google client credential
// from the google API. The resulting credential will be a RefreshToken scoped to the
// google cloud platform KMS api.
type GoogleCredential struct {
	Name string
}

// GoogleToken is the data structure to be used when serializing to token storage.
// This json object contains all the details needed to configure the client.
type GoogleToken struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	TheType      string `json:"type"`
}

// GoogleClientJSON is the wrapping object in a downloaded client configuration.
type GoogleClientJSON struct {
	ClientConfig GoogleClientConfig `json:"installed"`
}

// GoogleClientConfig is a struct wrapping the credential detail needed to provide sctl to identify
// itself to the google API.
type GoogleClientConfig struct {
	AuthProviderX509CertURL string   `json:"auth_provider_x509_cert_url"`
	AuthURI                 string   `json:"auth_uri"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ProjectID               string   `json:"project_id"`
	RedirectUris            []string `json:"redirect_uris"`
	TokenURI                string   `json:"token_uri"`
}

// DeleteCredential removes a stored credential from the system keystore, and
// will remove the assigned defualt credential from configuration.
func (gc GoogleCredential) DeleteCredential(credentialName string) error {
	return keyring.Delete(KeyNamespace, credentialName+"-gcp")
}

// SaveCredential marshals the received GoogleToken and stores the resulting json blob in the
// system keystore for secure storage at rest.
func (gc GoogleCredential) SaveCredential(credentialName string, credential GoogleToken) error {
	jsonData, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return keyring.Set(KeyNamespace, credentialName+"-gcp", string(jsonData))
}

// GetCredential returns a decoded GoogleToken from the system keystore. The resulting
// object is serializeable and should be used in conjunction with API Options configFromJSON()
func (gc GoogleCredential) GetCredential(credentialName string) (GoogleToken, error) {
	userTokenJSON, err := keyring.Get(KeyNamespace, credentialName+"-gcp")
	if err != nil {
		return GoogleToken{}, err
	}
	var token GoogleToken
	err = json.Unmarshal([]byte(userTokenJSON), &token)
	if err != nil {
		return GoogleToken{}, err
	}
	return token, nil
}

// JSON will attempt to return a byte array representation of a given google credential. This method
// passively checks for the environment variable GOOGLE_APPLICATION_CREDENTIALS and will short circuit
// based on this ENV VAR. Otherwise it tries to retrieve the default application credentials from the
// OS Keystore. If all else fails, it halts execution with helpful messaging on how to possibly correct
// the issue
func (gc GoogleCredential) JSON() ([]byte, error) {
	// This serializer method handles the override from ENV transparently
	// to the user. We should signal that we're loading from the ENV var
	// declared credential.
	external, exists := os.LookupEnv(CredentialVar)
	if exists {
		log.Debugf("Using env exported %s", CredentialVar)
		f, err := os.ReadFile(external)
		if err != nil {
			return []byte{}, errors.Wrapf(err, "Unable to read %s", CredentialVar)
		}
		return f, nil
	}

	tok, err := gc.GetCredential("default")
	if err != nil {
		log.Warn("Unable to locate credentials. Have you run `sctl credential add`?")
		log.WithFields(log.Fields{
			"key": CredentialVar,
		}).Warn("Another common issue is if running in a headless environment, where sctl expects" +
			" to be invoked with an environment variable set.")
		return []byte{}, err
	}
	return json.Marshal(tok)
}

// ValidateContext scans the environment for a declaration of authentication via ENV
// In the case of the GCP provider, we scan for GOOGLE_APPLICAITON_CREDENTIALS and return
// an error if the environment variable is declared.
func (gc GoogleCredential) ValidateContext() error {
	_, isSet := os.LookupEnv(CredentialVar)
	if isSet {
		return fmt.Errorf("environment Variable %s is present, and will prevent sctl from using any user configured credentials", CredentialVar)
	}

	return nil
}

func (gc GoogleCredential) formatCredential(token *oauth2.Token, rawClientData []byte) (GoogleToken, error) {
	var clientJSON GoogleClientJSON
	err := json.Unmarshal(rawClientData, &clientJSON)
	if err != nil {
		return GoogleToken{}, err
	}

	return GoogleToken{
		ClientID:     clientJSON.ClientConfig.ClientID,
		ClientSecret: clientJSON.ClientConfig.ClientSecret,
		RefreshToken: token.RefreshToken,
		TheType:      "authorized_user",
	}, nil
}

// Login initiates a CLI workflow to authenticate the user with offline credentials limited to
// the KMS scope
func (gc GoogleCredential) Login(c utils.Configuration, credentialName string, port int) error {
	err := gc.ValidateContext()
	if err != nil {
		log.Printf("Configuration issue detected. %v", err)
	}
	// Encode the Client Configuration json as a byte stream
	clientConfig := []byte(c.GoogleClient.Data)
	// Initialize the API client
	config, err := google.ConfigFromJSON(clientConfig, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		return err
	}
	// Initiate login sequence
	tok, err := gc.getToken(config, port)
	if err != nil {
		return err
	}
	userToken, err := gc.formatCredential(tok, clientConfig)
	if err != nil {
		return err
	}
	return gc.SaveCredential(credentialName, userToken)
}

func (gc GoogleCredential) getToken(config *oauth2.Config, port int) (*oauth2.Token, error) {

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	var authCode string

	// Spin up a temporary http server
	wg := &sync.WaitGroup{}
	wg.Add(1)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authCode = r.URL.Query().Get("code")
		if authCode != "" && r.URL.Query().Get("state") == state {
			// We could make this prettier, with some html/css?
			fmt.Fprintln(w, "Authorization successful. You can close this window and return to sctl.")
			wg.Done()
		}
	})

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
	}()

	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	// wait for the user to visit the url and go through the oauth flow
	wg.Wait()

	// need to get the token from the server
	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve token from web")
	}
	return tok, nil
}
