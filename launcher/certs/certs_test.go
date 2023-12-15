package certs

import (
	"fmt"
	"log"
	"testing"
)

func TestCert(t *testing.T) {
	cert, key, err := GenCert("testvm")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(cert))
	fmt.Println(key)
}
