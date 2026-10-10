package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordValidation(t *testing.T) {
	if err := validatePasswordStrength([]byte("Short1!")); err == nil {
		t.Error("expected error for short password")
	}
	// Lacks the required complexity groups but contains no separately rejected
	// weak pattern, so this exercises the complexity check on its own.
	if err := validatePasswordStrength([]byte("abcdEFGHijkl")); err == nil {
		t.Error("expected error for lacking complexity")
	}
	if err := validatePasswordStrength([]byte("Password12345!")); err == nil {
		t.Error("expected error for common weak pattern")
	}
	if err := validatePasswordStrength([]byte("Correct-Horse-Battery-Staple-99!")); err != nil {
		t.Errorf("unexpected error for strong password: %v", err)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	inPath := filepath.Join(tmpDir, "plaintext.txt")
	encPath := filepath.Join(tmpDir, "encrypted.enc")
	decPath := filepath.Join(tmpDir, "decrypted.txt")

	originalData := []byte("Hello, ChaChaCrypt secure world! This is a comprehensive test of chunked AEAD encryption.")
	if err := os.WriteFile(inPath, originalData, 0600); err != nil {
		t.Fatalf("failed to write test input: %v", err)
	}

	password := []byte("StrongP@ssw0rd2026!")

	err := encryptFile(
		ctx,
		inPath,
		encPath,
		password,
		minArgonTime,
		minArgonMemory,
		minArgonThreads,
		defaultChunkSize,
		true,
		false,
	)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	err = decryptFile(ctx, encPath, decPath, password, true, false)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	decryptedData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Errorf("decrypted data does not match original: got %q, want %q", decryptedData, originalData)
	}
}

func TestTamperedHeader(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	inPath := filepath.Join(tmpDir, "plaintext.txt")
	encPath := filepath.Join(tmpDir, "encrypted.enc")
	decPath := filepath.Join(tmpDir, "decrypted.txt")

	if err := os.WriteFile(inPath, []byte("Secret data"), 0600); err != nil {
		t.Fatal(err)
	}

	password := []byte("StrongP@ssw0rd2026!")
	if err := encryptFile(
		ctx,
		inPath,
		encPath,
		password,
		minArgonTime,
		minArgonMemory,
		minArgonThreads,
		defaultChunkSize,
		true,
		false,
	); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	data[20] ^= 0xFF

	if err := os.WriteFile(encPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := decryptFile(ctx, encPath, decPath, password, true, false); err == nil {
		t.Error("expected error when decrypting file with tampered header, got nil")
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	inPath := filepath.Join(tmpDir, "plaintext.txt")
	encPath1 := filepath.Join(tmpDir, "encrypted1.enc")
	encPath2 := filepath.Join(tmpDir, "encrypted2.enc")
	decPath := filepath.Join(tmpDir, "decrypted.txt")

	originalData := []byte("Data for key rotation test.")
	if err := os.WriteFile(inPath, originalData, 0600); err != nil {
		t.Fatal(err)
	}

	oldPass := []byte("OldStrongP@ss1!")
	newPass := []byte("NewStrongP@ss2!")

	if err := encryptFile(
		ctx,
		inPath,
		encPath1,
		oldPass,
		minArgonTime,
		minArgonMemory,
		minArgonThreads,
		defaultChunkSize,
		true,
		false,
	); err != nil {
		t.Fatal(err)
	}

	if err := rotateFile(
		ctx,
		encPath1,
		encPath2,
		oldPass,
		newPass,
		minArgonTime,
		minArgonMemory,
		minArgonThreads,
		true,
		false,
	); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	if err := decryptFile(ctx, encPath2, decPath, oldPass, true, false); err == nil {
		t.Error("expected decryption to fail with old password after rotation")
	}

	if err := decryptFile(ctx, encPath2, decPath, newPass, true, false); err != nil {
		t.Fatalf("decryption with new password failed: %v", err)
	}

	decryptedData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalData, decryptedData) {
		t.Errorf("rotated decrypted data mismatch: got %q, want %q", decryptedData, originalData)
	}
}

func TestPathSafety(t *testing.T) {
	_, err := safeOutputPath("../outside.txt", false)
	if err == nil {
		t.Error("expected error for path traversal reference")
	}
}
