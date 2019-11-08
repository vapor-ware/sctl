package utils

import (
	"testing"
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
	if len(s) != 1 {
		t.Errorf("Unexpected length, Wanted: 1  Got: %v", len(s))
	}
	if s[0].Name != "DOUBLEMINT" {
		t.Errorf("Unexpected Element, Wanted: DOUBLEMINT  Got: %s", s[0].Name)
	}
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

	if len(s) != 1 {
		t.Errorf("Unexpected length, Wanted: 1  Got: %v", len(s))
	}

	if s[0].Cyphertext != "123TOADD" {
		t.Errorf("Unexpected Cyphertext, Wanted: 123TOADD  Got: %s", s[0].Cyphertext)
	}

}

func TestV2SameKey(t *testing.T) {
	s := V2{}
	expectTrue := s.SameKey("no")

	// This is basically first init check. It should debug warn if run with --debug.
	if expectTrue != true {
		t.Errorf("Expected SameKey to eval to true on condition: len secrets: %v, len KeyIdentifier: %v", len(s.Secrets), len(s.KeyIdentifier))
	}

	// Setup a post-V2 semi-migration path. We have secrets, but no KeyIdentifier. Presume that
	// the operator knows what they are doing and save the file
	s.Secrets = Secrets{Secret{Name: "Test", Cyphertext: "Test"}}
	expectTrue = s.SameKey("yes")
	if expectTrue != true {
		t.Errorf("Expected SameKey to eval to true on condition: len secrets: %v, len KeyIdentifier: %v", len(s.Secrets), len(s.KeyIdentifier))
	}

	s.KeyIdentifier = "wont-match"
	expectFalse := s.SameKey("no")

	// Check for the usual case of having secrets and having a key identifier to gate writes
	if expectFalse != false {
		t.Errorf("Expected SameKey to eval to false on condition: len secrets: %v, len KeyIdentifier: %v", len(s.Secrets), len(s.KeyIdentifier))
	}
}

// This test is largely useless. The GetVersion method returns a static "2" string.
// So we'll just make sure we get 2 from V2 so we dont accidentally break it.
func TestV2GetVersion(t *testing.T) {
	s := V2{}
	if s.GetVersion() != "2" {
		t.Errorf("Version identifier error. Expected: 2  Got: %v", s.GetVersion())
	}
}

func TestV2Load(t *testing.T) {
	s := V2{}

	s.Filepath = "../testdata/non-existant.json"
	err := s.Load()

	if err != nil {
		t.Errorf("Unexpected behavior. FileNotFound errors should silently be masked.")
	}

	s.Filepath = "../testdata/test_secret_v2.json"
	err = s.Load()

	if err != nil {
		t.Errorf("Unexpected error processing envelope: %v", err)
	}
	if len(s.Secrets) != 1 {
		t.Errorf("Unexpected length of secrets. Wanted: 1  Got: %v", len(s.Secrets))
	}

}
