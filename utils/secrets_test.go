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
