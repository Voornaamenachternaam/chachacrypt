package main

import (
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Length 12", 12},
		{"Length 15", 15},
		{"Length 20", 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := generatePassword(tt.length)
			if len(password) != tt.length {
				t.Errorf("generatePassword() length = %v, want %v", len(password), tt.length)
			}
			// Check for at least one character from each set
			sets := []string{
				"abcdefghijklmnopqrstuvwxyz",
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
				"0123456789",
				"`~!@#$%^&*()_+-={}|[]\\;':\",./<>?",
			}
			for _, set := range sets {
				if !strings.ContainsAny(password, set) {
					t.Errorf("generatePassword() missing character from set: %s", set)
				}
			}
		})
	}
}

func TestGeneratePasswordTooShort(t *testing.T) {
	// Test that generatePassword handles short length appropriately
	// Since it uses log.Fatal, we can't recover from it in a test
	// We'll just verify that it doesn't return a password for short lengths
	// by checking the length of the output
	if len(generatePassword(11)) > 0 {
		t.Errorf("generatePassword() should not return a password for short length")
	}
}

func TestEncryptDecryptFile(t *testing.T) {
	// Create a temporary file with content
	content := "This is a test file content for encryption and decryption."
	tmpFile, err := os.CreateTemp("", "testfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Encrypt the file
	password := "strongPassword123!"
	encryptedFile := tmpFile.Name() + ".enc"
	defer os.Remove(encryptedFile)
	if err := encryptFile(tmpFile.Name(), encryptedFile, password); err != nil {
		t.Fatalf("encryptFile() error = %v", err)
	}

	// Decrypt the file
	decryptedFile := tmpFile.Name() + ".dec"
	defer os.Remove(decryptedFile)
	if err := decryptFile(encryptedFile, decryptedFile, password); err != nil {
		t.Fatalf("decryptFile() error = %v", err)
	}

	// Read the decrypted content
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(decryptedContent) != content {
		t.Errorf("decrypted content = %v, want %v", string(decryptedContent), content)
	}
}

func TestEncryptDecryptFileWrongPassword(t *testing.T) {
	// Create a temporary file with content
	content := "This is a test file content."
	tmpFile, err := os.CreateTemp("", "testfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Encrypt the file
	password := "correctPassword"
	encryptedFile := tmpFile.Name() + ".enc"
	defer os.Remove(encryptedFile)
	if err := encryptFile(tmpFile.Name(), encryptedFile, password); err != nil {
		t.Fatalf("encryptFile() error = %v", err)
	}

	// Decrypt with wrong password
	wrongPassword := "wrongPassword"
	decryptedFile := tmpFile.Name() + ".dec"
	defer os.Remove(decryptedFile)
	err = decryptFile(encryptedFile, decryptedFile, wrongPassword)
	if err == nil {
		t.Errorf("decryptFile() should fail with wrong password")
	}
}

func TestValidateFileInput(t *testing.T) {
	tests := []struct {
		name        string
		inputFile   string
		outputFile  string
		expectError bool
	}{
		{"Valid", "testdata/test.txt", "output.txt", false},
		{"MissingInput", "", "output.txt", true},
		{"MissingOutput", "testdata/test.txt", "", true},
		{"NonExistentInput", "nonexistent.txt", "output.txt", true},
	}
	// Create testdata directory and file
	os.Mkdir("testdata", 0755)
	os.WriteFile("testdata/test.txt", []byte("test"), 0644)
	defer os.RemoveAll("testdata")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFileInput(tt.inputFile, tt.outputFile)
			if (err != nil) != tt.expectError {
				t.Errorf("validateFileInput() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestReadPassword(t *testing.T) {
	// This test is tricky because readPassword uses terminal input.
	// We can mock os.Stdin or skip this test in automated environments.
	// For now, skip since it requires user input.
	t.Skip("Skipping test because it requires terminal input")
}

func TestSafeUintConversions(t *testing.T) {
	// Test safeUint8
	if _, err := safeUint8(-1); err == nil {
		t.Error("safeUint8 should return error for negative values")
	}
	if _, err := safeUint8(256); err == nil {
		t.Error("safeUint8 should return error for values > 255")
	}
	if val, err := safeUint8(128); err != nil || val != 128 {
		t.Errorf("safeUint8(128) = %v, %v, want 128, nil", val, err)
	}

	// Test safeUint32
	if _, err := safeUint32(-1); err == nil {
		t.Error("safeUint32 should return error for negative values")
	}
	if val, err := safeUint32(1000); err != nil || val != 1000 {
		t.Errorf("safeUint32(1000) = %v, %v, want 1000, nil", val, err)
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{"Valid", "file.txt", false},
		{"Absolute", "/absolute/path", true},
		{"Traversal", "../file.txt", true},
		{"DoubleTraversal", "../../file.txt", true},
		{"CurrentDir", "./file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("validateFilePath(%s) error = %v, expectError %v", tt.path, err, tt.expectError)
			}
		})
	}
}
