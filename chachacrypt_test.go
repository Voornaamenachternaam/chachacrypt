package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestConstantTimeEqual checks equal and non-equal cases.
func TestConstantTimeEqual(t *testing.T) {
	a := []byte("same")
	b := []byte("same")
	if !ConstantTimeEqual(a, b) {
		t.Fatalf("expected equal slices to return true")
	}

	c := []byte("diff")
	if ConstantTimeEqual(a, c) {
		t.Fatalf("expected different slices to return false")
	}

	d := []byte("short")
	if ConstantTimeEqual(a, d) {
		t.Fatalf("expected different-length slices to return false")
	}
}

// TestValidateSaltUniqueness ensures salt cache rejects reuse.
func TestValidateSaltUniqueness(t *testing.T) {
	// reset global cache to avoid cross-test pollution
	saltMu.Lock()
	saltCache = make(map[string][]byte)
	saltMu.Unlock()

	salt := []byte{0x01, 0x02, 0x03, 0x04}
	if err := validateSaltUniqueness(salt); err != nil {
		t.Fatalf("unexpected error on first uniqueness check: %v", err)
	}
	if err := validateSaltUniqueness(salt); err == nil {
		t.Fatalf("expected error when reusing salt, got nil")
	}
}

// TestCreateAndVerifyIntegrity ensures createFileIntegrity and verifyFileIntegrity cooperate.
func TestCreateAndVerifyIntegrity(t *testing.T) {
	cfg := config{
		SaltSize:   16,
		KeySize:    32,
		KeyTime:    1,
		KeyMemory:  32,
		KeyThreads: 1,
		ChunkSize:  1024,
		NonceSize:  chacha20poly1305.NonceSizeX,
		KeyVersion: 1,
	}

	header, err := createHeader(cfg)
	if err != nil {
		t.Fatalf("createHeader failed: %v", err)
	}

	salt := bytes.Repeat([]byte{0xAA}, int(header.SaltSize))
	integrity, err := createFileIntegrity(header, salt)
	if err != nil {
		t.Fatalf("createFileIntegrity failed: %v", err)
	}
	header.Integrity = integrity

	if err := verifyFileIntegrity(header, salt); err != nil {
		t.Fatalf("verifyFileIntegrity failed: %v", err)
	}
}

// TestBuildEnhancedAAD confirms determinism and sequence-sensitivity.
func TestBuildEnhancedAAD(t *testing.T) {
	cfg := config{
		SaltSize:   8,
		KeySize:    32,
		KeyTime:    1,
		KeyMemory:  32,
		KeyThreads: 1,
		ChunkSize:  512,
		NonceSize:  chacha20poly1305.NonceSizeX,
		KeyVersion: 1,
	}
	header, err := createHeader(cfg)
	if err != nil {
		t.Fatalf("createHeader failed: %v", err)
	}

	a1, err := buildEnhancedAAD(header, 1)
	if err != nil {
		t.Fatalf("buildEnhancedAAD failed: %v", err)
	}
	a2, err := buildEnhancedAAD(header, 2)
	if err != nil {
		t.Fatalf("buildEnhancedAAD failed: %v", err)
	}
	if bytes.Equal(a1, a2) {
		t.Fatalf("expected AAD to differ between sequences")
	}

	a1b, err := buildEnhancedAAD(header, 1)
	if err != nil {
		t.Fatalf("buildEnhancedAAD failed: %v", err)
	}
	if !bytes.Equal(a1, a1b) {
		t.Fatalf("expected deterministic AAD for same inputs")
	}
}

// TestEncryptDecryptChunkRoundTrip performs a round-trip encryption/decryption of a chunk.
func TestEncryptDecryptChunkRoundTrip(t *testing.T) {
	cfg := config{
		SaltSize:   12,
		KeySize:    32,
		KeyTime:    1,
		KeyMemory:  32,
		KeyThreads: 1,
		ChunkSize:  1024,
		NonceSize:  chacha20poly1305.NonceSizeX,
		KeyVersion: 1,
	}
	header, err := createHeader(cfg)
	if err != nil {
		t.Fatalf("createHeader failed: %v", err)
	}

	// deterministic salt for test
	salt := bytes.Repeat([]byte{0x02}, int(header.SaltSize))
	integrity, err := createFileIntegrity(header, salt)
	if err != nil {
		t.Fatalf("createFileIntegrity failed: %v", err)
	}
	header.Integrity = integrity

	// derive key (with small argon2 params chosen for test speed)
	keyBuf, err := deriveKey([]byte("testpassword"), salt, header)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	defer keyBuf.Close()

	aead, err := chacha20poly1305.NewX(keyBuf.Bytes())
	if err != nil {
		t.Fatalf("NewX failed: %v", err)
	}
	header.NonceSize = uint32(aead.NonceSize())

	tmpf, err := os.CreateTemp("", "chunk-*")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer func() {
		name := tmpf.Name()
		tmpf.Close()
		os.Remove(name)
	}()

	plain := []byte("hello world — the quick brown fox jumps over the lazy dog")
	if err := encryptChunk(tmpf, plain, aead, nil, 1, header); err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	if _, err := tmpf.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek failed: %v", err)
	}

	got, err := decryptChunk(tmpf, aead, nil, 1, header)
	if err != nil {
		t.Fatalf("decryptChunk failed: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", string(got), string(plain))
	}
}
