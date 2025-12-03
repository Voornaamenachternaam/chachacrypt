package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

// TestGetPassword verifies the random password generator.
func TestGetPassword(t *testing.T) {
	length := 20
	pw := getPassword(length)
	if len(pw) != length {
		t.Errorf("getPassword(%d) length = %d; want %d", length, len(pw), length)
	}
	// Ensure no control characters or spaces in password.
	for _, c := range pw {
		if c == ' ' || c == '\n' || c == '\t' {
			t.Errorf("getPassword generated invalid char %q", c)
		}
	}
}

// TestEncryptDecrypt performs a full encrypt/decrypt cycle.
func TestEncryptDecrypt(t *testing.T) {
	// Create a temporary plaintext file.
	data := []byte("The quick brown fox jumps over the lazy dog")
	inFile, err := ioutil.TempFile("", "plaintext*.txt")
	if err != nil {
		t.Fatalf("TempFile error: %v", err)
	}
	defer os.Remove(inFile.Name())
	if _, err := inFile.Write(data); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	inFile.Close()

	// Define encrypted and decrypted filenames.
	encFile := inFile.Name() + ".enc"
	decFile := inFile.Name() + ".dec"
	defer os.Remove(encFile)
	defer os.Remove(decFile)

	// Simulate interactive password input for encryption.
	password := []byte("TestPassword123")
	// Use os.Pipe to feed the password twice (for confirmation).
	origStdin := os.Stdin
	r1, w1, _ := os.Pipe()
	w1.Write(append(password, '\n'))
	w1.Write(append(password, '\n'))
	w1.Close()
	os.Stdin = r1
	// Call the encryption logic (assumes encryption(inFile, encFile) reads from stdin).
	encryption(inFile.Name(), encFile)
	os.Stdin = origStdin

	// Now decrypt using the same password.
	r2, w2, _ := os.Pipe()
	w2.Write(append(password, '\n'))
	w2.Close()
	os.Stdin = r2
	decryption(encFile, decFile)
	os.Stdin = origStdin

	// Verify decrypted content matches original.
	result, err := ioutil.ReadFile(decFile)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("Decrypted data = %q; want %q", result, data)
	}
}

// TestEncryptMissingFile ensures encryption fails on a non-existent input.
func TestEncryptMissingFile(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic on missing input file, but none occurred")
		}
	}()
	// Call encryption with a non-existent file; should panic.
	encryption("file_does_not_exist.txt", "out.enc")
}
