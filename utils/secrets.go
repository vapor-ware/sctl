package utils

import (
	"log"
	"time"
)

// Secret contains data and metadata related to a scuttle-managed secret.
//
// An example JSON-serialized secret:
//
//    {
//      "name": "A_SECRET",
//      "cypher": "0xD34DB33F",
//      "created": "2019-05-01 13:01:27.189242799 -0500 CDT m=+0.000075907",
//      "encoding": "plain"
//     }
type Secret struct {
	Name       string    `json:"name"`
	Cyphertext string    `json:"cypher"`
	Created    time.Time `json:"created"`
	Encoding   string    `json:"encoding"`
}

// Secrets - A collection of Secret
type Secrets []Secret

// Remove -  a secret from the collection
func (s *Secrets) Remove(name string) {
	for index, element := range *s {
		if element.Name == name {
			log.Printf("Removing entry %s", element.Name)
			*s = append((*s)[:index], (*s)[index+1:]...)
		}
	}
}

// Add - Upsert a secret into the collection. If a key exists,
// it will presume rotation, and update in-place.
func (s *Secrets) Add(toAdd Secret) {
	// Adds or Updates a secret
	for index, element := range *s {
		if element.Name == toAdd.Name {
			log.Printf("Rotating entry %s", element.Name)
			*s = append((*s)[:index], (*s)[index+1:]...)
		}
	}
	*s = append((*s), toAdd)
}
