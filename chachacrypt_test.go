package main

import (
    "testing"
)

func TestGetPassword(t *testing.T) {
    _, err := getPassword(0)
    if err != getPasswordError {
        t.Errorf("Expected getPasswordError, got %v", err)
    }
    pw, err := getPassword(10)
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
    if len(pw) != 10 {
        t.Errorf("Expected password length 10, got %d", len(pw))
    }
}

func TestEncryptionErrorConstant(t *testing.T) {
    err := encryptFile("", "")
    if err != encryptionError {
        t.Errorf("Expected encryptionError, got %v", err)
    }
}

func TestDecryptionErrorConstant(t *testing.T) {
    err := decryptFile("", "")
    if err != decryptionError {
        t.Errorf("Expected decryptionError, got %v", err)
    }
}

func TestEncryptionFailConstant(t *testing.T) {
    if encryptionFAIL == nil {
        t.Errorf("Expected encryptionFAIL to be defined")
     }
}
