package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretRemove(t *testing.T) {
	s := Secrets{
		Secret{
			Name:       "TEST",
			Cyphertext: "ABC123",
		},
		Secret{
			Name:       "DOUBLEMINT",
			Cyphertext: "123ABC",
		},
	}

	s.Remove("TEST")
	assert.Len(t, s, 1)
	assert.Equal(t, "DOUBLEMINT", s[0].Name)
}

func TestSecretAddRotation(t *testing.T) {
	s := Secrets{}
	s.Add(Secret{
		Name:       "TOADD",
		Cyphertext: "TOADD123",
	})
	s.Add(Secret{
		Name:       "TOADD",
		Cyphertext: "123TOADD",
	})

	assert.Len(t, s, 1)
	assert.Equal(t, "123TOADD", s[0].Cyphertext)
}

func TestSecretFind(t *testing.T) {
	s := Secrets{}
	s.Add(Secret{
		Name:       "TEST",
		Cyphertext: "123TEST",
	})

	found, err := s.Find("TEST")
	assert.NoError(t, err)
	assert.Equal(t, "TEST", found.Name)
	assert.Equal(t, "123TEST", found.Cyphertext)
}

func TestSecretFindRaisesError(t *testing.T) {
	s := Secrets{}
	s.Add(Secret{
		Name:       "TEST",
		Cyphertext: "123TEST",
	})

	_, err := s.Find("NO")
	assert.Error(t, err)
}

func TestV2SameKeyV2Migration(t *testing.T) {
	s := V2{}

	// Setup a post-V2 semi-migration path. We have secrets, but no KeyIdentifier. Presume that
	// the operator knows what they are doing and save the file
	s.Secrets = Secrets{Secret{Name: "Test", Cyphertext: "Test"}}
	expectTrue := s.SameKey("yes")
	assert.True(t, expectTrue)
}

// Check for the usual case of having secrets and having a key identifier to gate writes
func TestV2SameKeyDifferentKeys(t *testing.T) {
	s := V2{}
	s.KeyIdentifier = "wont-match"
	expectFalse := s.SameKey("no")
	assert.False(t, expectFalse)
}

func TestV2SameKeySameKeys(t *testing.T) {
	s := V2{}
	s.KeyIdentifier = "sames"
	expectTrue := s.SameKey("sames")
	assert.True(t, expectTrue)
}

// This test is largely useless. The GetVersion method returns a static "2" string.
// So we'll just make sure we get 2 from V2 so we dont accidentally break it.
func TestV2GetVersion(t *testing.T) {
	s := V2{}
	assert.Equal(t, "2", s.GetVersion())
}

func TestV2LoadNonExistant(t *testing.T) {
	s := V2{}

	s.Filepath = "../testdata/non-existant.json"
	err := s.Load()

	// File not found errors should be silently masked in this case.
	assert.NoError(t, err)
}

func TestV2LoadSecretV2(t *testing.T) {
	s := V2{}
	s.Filepath = "../testdata/test_secret_v2.json"
	err := s.Load()

	assert.NoError(t, err)
	assert.Len(t, s.Secrets, 1)
}
