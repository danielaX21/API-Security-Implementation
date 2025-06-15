package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	passwords := []string{"pass1", "admin123"}

	for _, p := range passwords {
		hash, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		fmt.Printf("Parola: %s -> Hash: %s\n", p, string(hash))
	}
}
