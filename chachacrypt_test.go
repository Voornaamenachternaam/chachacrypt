// chachacrypt_test.go
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// --- Helper Functions for Testing ---

func createTempFile(t *testing.T, dir string, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(dir, "testfile_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	return f.Name()
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}
	return b
}

func getTestPassword() *SecureBuffer {
	sb := NewSecureBuffer(12)
	copy(sb.Bytes(), []byte("correct-horse"))
	return sb
}

func getTestConfig() config {
	return config{
		SaltSize:   16, // Min allowed for speed
		KeySize:    32,
		KeyTime:    3, // Min allowed for speed
		KeyMemory:  128 * 1024,
		KeyThreads: 1,
		ChunkSize:  1024,
		NonceSize:  chacha20poly1305.NonceSizeX,
		KeyVersion: 1,
	}
}

// --- Unit Tests ---

func TestSecureBuffer_Lifecycle(t *testing.T) {
	size := 32
	sb := NewSecureBuffer(size)
	if len(sb.Bytes()) != size {
		t.Errorf("Expected buffer size %d, got %d", size, len(sb.Bytes()))
	}
	testData := []byte("test data for secure buffer")
	copy(sb.Bytes(), testData)
	if !bytes.Contains(sb.Bytes(), testData[:5]) {
		t.Error("Buffer does not contain written data")
	}
	sb.Zero()
	if !sb.IsZeroed() {
		t.Error("Buffer should report being zeroed")
	}
	allZero := true
	for _, b := range sb.Bytes() {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("Buffer content was not actually zeroed")
	}
	sb.Zero()
	if !sb.IsZeroed() {
		t.Error("Buffer should still be zeroed")
	}
	if err := sb.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestMinInt(t *testing.T) {
	if minInt(1, 2) != 1 {
		t.Error("minInt(1, 2) should be 1")
	}
	if minInt(10, 5) != 5 {
		t.Error("minInt(10, 5) should be 5")
	}
	if minInt(-1, -5) != -5 {
		t.Error("minInt(-1, -5) should be -5")
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"valid/path.txt", false},
		{"file.txt", false},
		{"", true},
		{"/abs/path", true},
		{"../parent", true},
		{"subdir/../traversal", true},
	}

	for _, tt := range tests {
		err := validateFilePath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateFilePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
		}
	}
}

func TestBuildConfig(t *testing.T) {
	// Valid config
	_, err := buildConfig(3, 128*1024, 1, 1024, 16, 32, 1)
	if err != nil {
		t.Errorf("Valid config failed: %v", err)
	}
	failures := []struct {
		time, mem, threads, chunk, salt, key int
		name                                 string
	}{
		{2, 128 * 1024, 1, 1024, 16, 32, "Time too low"},
		{maxArgonTime + 1, 128 * 1024, 1, 1024, 16, 32, "Time too high"},
		{3, 64 * 1024, 1, 1024, 16, 32, "Mem too low"},
		{3, 128 * 1024, 0, 1024, 16, 32, "Threads too low"},
		{3, 128 * 1024, 1, 500, 16, 32, "Chunk too small"},
		{3, 128 * 1024, 1, 1024, 10, 32, "Salt too small"},
		{3, 128 * 1024, 1, 1024, 16, 10, "Key too small"},
	}

	for _, f := range failures {
		_, err := buildConfig(f.time, f.mem, f.threads, f.chunk, f.salt, f.key, 1)
		if err == nil {
			t.Errorf("Expected error for %s, got nil", f.name)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	length := 20
	pw, err := generatePassword(length)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}
	if len(pw) != length {
		t.Errorf("Expected length %d, got %d", length, len(pw))
	}
	same := true
	for i := 1; i < len(pw); i++ {
		if pw[i] != pw[0] {
			same = false
			break
		}
	}
	if same {
		t.Error("Password has zero entropy (all same chars)")
	}
	_, err = generatePassword(0)
	if err == nil {
		t.Error("Expected error for 0 length password")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte("a"), []byte("a")) {
		t.Error("Equal bytes should return true")
	}
	if ConstantTimeEqual([]byte("a"), []byte("b")) {
		t.Error("Different bytes should return false")
	}
	if ConstantTimeEqual([]byte("a"), []byte("aa")) {
		t.Error("Different lengths should return false")
	}
}

func TestSaltUniqueness(t *testing.T) {
	// Reset cache for test
	saltMu.Lock()
	saltCache = make(map[string][]byte)
	saltMu.Unlock()

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if err := validateSaltUniqueness(salt); err != nil {
		t.Errorf("First use of salt failed: %v", err)
	}
	if err := validateSaltUniqueness(salt); err == nil {
		t.Error("Duplicate salt did not trigger error")
	}
	salt2 := make([]byte, 16)
	// Ensure salt2 is different
	salt2[0] = ^salt[0]
	if err := validateSaltUniqueness(salt2); err != nil {
		t.Errorf("Different salt failed: %v", err)
	}
}

// --- Integration Tests ---

func TestEncryptionDecryption_EndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	originalContent := make([]byte, 1024*5+100)
	if _, err := rand.Read(originalContent); err != nil {
		t.Fatal(err)
	}
	inputFile := createTempFile(t, tempDir, originalContent)
	encryptedFile := filepath.Join(tempDir, "output.enc")
	decryptedFile := filepath.Join(tempDir, "restored.txt")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()

	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, encryptedFile, pw, cfg); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	encStats, err := os.Stat(encryptedFile)
	if err != nil {
		t.Fatalf("Encrypted file missing: %v", err)
	}
	if encStats.Size() == 0 {
		t.Fatal("Encrypted file is empty")
	}
	if err := decryptFile(ctx, encryptedFile, decryptedFile, pw.Bytes(), cfg); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	restoredContent := readFile(t, decryptedFile)
	if !bytes.Equal(originalContent, restoredContent) {
		t.Error("Restored content does not match original")
	}
}

func TestWrongPassword(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := createTempFile(t, tempDir, []byte("secret data"))
	encryptedFile := filepath.Join(tempDir, "output.enc")
	decryptedFile := filepath.Join(tempDir, "restored.txt")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()
	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, encryptedFile, pw, cfg); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	wrongPw := []byte("wrong-password")
	err := decryptFile(ctx, encryptedFile, decryptedFile, wrongPw, cfg)
	if err == nil {
		t.Fatal("Decryption should fail with wrong password")
	}
	if !strings.Contains(err.Error(), "processing failed") && !strings.Contains(err.Error(), "cipher") {
		t.Logf("Got expected error type: %v", err)
	}
}

func TestIntegrityCheck_TamperHeader(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := createTempFile(t, tempDir, []byte("integrity test"))
	encryptedFile := filepath.Join(tempDir, "tamper.enc")
	decryptedFile := filepath.Join(tempDir, "tamper.out")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()
	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, encryptedFile, pw, cfg); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	data := readFile(t, encryptedFile)

	// Tamper with Magic Number (start of file)
	data[0] = 'X'
	if err := os.WriteFile(encryptedFile, data, 0644); err != nil {
		t.Fatal(err)
	}
	err := decryptFile(ctx, encryptedFile, decryptedFile, pw.Bytes(), cfg)
	if err == nil {
		t.Error("Decryption should fail on invalid magic number")
	} else if !strings.Contains(err.Error(), "invalid file format") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestIntegrityCheck_TamperMetadata(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := createTempFile(t, tempDir, []byte("integrity test metadata"))
	encryptedFile := filepath.Join(tempDir, "tamper_meta.enc")
	decryptedFile := filepath.Join(tempDir, "tamper_meta.out")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()
	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, encryptedFile, pw, cfg); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	data := readFile(t, encryptedFile)

	// Tamper with Argon parameters (offset ~9 bytes in: magic(8) + ver(1))
	// Header struct: Magic(8), Ver(1), ArgonTime(4)...
	// Let's modify ArgonTime
	data[9]++
	if err := os.WriteFile(encryptedFile, data, 0644); err != nil {
		t.Fatal(err)
	}
	err := decryptFile(ctx, encryptedFile, decryptedFile, pw.Bytes(), cfg)
	if err == nil {
		t.Error("Decryption should fail on tampered metadata (HMAC mismatch)")
	} else if !strings.Contains(err.Error(), "integrity") && !strings.Contains(err.Error(), "tamper") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := createTempFile(t, tempDir, []byte("data to rotate"))
	encryptedFile := filepath.Join(tempDir, "rotate.enc")
	rotatedFile := filepath.Join(tempDir, "rotated.enc")
	decryptedFile := filepath.Join(tempDir, "restored.txt")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()
	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, encryptedFile, pw, cfg); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	newVersion := byte(2)
	if err := rotateKey(ctx, encryptedFile, rotatedFile, pw.Bytes(), newVersion); err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}
	if err := decryptFile(ctx, rotatedFile, decryptedFile, pw.Bytes(), cfg); err != nil {
		t.Fatalf("Decryption of rotated file failed: %v", err)
	}
	if !bytes.Equal(readFile(t, decryptedFile), []byte("data to rotate")) {
		t.Error("Content corrupted after rotation")
	}
	f, err := os.Open(rotatedFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	if header.KeyVersion != newVersion {
		t.Errorf("Expected key version %d, got %d", newVersion, header.KeyVersion)
	}
}

func TestContextCancellation(t *testing.T) {
	// Create a large file to ensure we can catch it mid-process
	tempDir := t.TempDir()
	largeData := make([]byte, 1024*1024) // 1MB
	inputFile := createTempFile(t, tempDir, largeData)
	outputFile := filepath.Join(tempDir, "cancel.enc")

	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before start

	err := encryptFile(ctx, inputFile, outputFile, pw, cfg)
	if err == nil {
		t.Error("Expected error on cancelled context")
	} else if err != context.Canceled {
		if !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("Expected context canceled error, got: %v", err)
		}
	}
}

func TestPaddingCheck(t *testing.T) {
	// Generate a valid header
	cfg := getTestConfig()
	header, err := createHeader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	header.Padding[0] = 1

	// Serialize
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	tempDir := t.TempDir()
	badFile := filepath.Join(tempDir, "bad_padding.bin")
	if err := os.WriteFile(badFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(badFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = readHeader(f)
	if err == nil {
		t.Error("Should fail when padding is non-zero")
	}
}

func TestEntropyCheck(t *testing.T) {
	// This tests the CSPRNGReader's checkEntropy logic
	rng := &CSPRNGReader{}
	lowEntropy := make([]byte, 4096)
	if err := rng.checkEntropy(lowEntropy); err == nil {
		t.Error("Expected error for low entropy sample")
	}
	highEntropy := make([]byte, 4096)
	if _, err := rand.Read(highEntropy); err != nil {
		t.Fatal(err)
	}
	if err := rng.checkEntropy(highEntropy); err != nil {
		t.Errorf("High entropy sample failed check: %v", err)
	}
	small := make([]byte, 10)
	if err := rng.checkEntropy(small); err != nil {
		t.Errorf("Small sample should pass (skip): %v", err)
	}
}

func TestConcurrentProcessing(t *testing.T) {
	// Ensure no race conditions in global state (salt cache) or shared logic
	var wg sync.WaitGroup
	count := 5 // parallel executions

	tempDir := t.TempDir()
	pw := getTestPassword()
	defer pw.Close()
	cfg := getTestConfig()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fName := fmt.Sprintf("file_%d.txt", idx)
			inPath := filepath.Join(tempDir, fName)
			outPath := filepath.Join(tempDir, fName+".enc")
			if err := os.WriteFile(inPath, []byte(fName), 0644); err != nil {
				t.Error(err)
				return
			}
			ctx := context.Background()
			if err := encryptFile(ctx, inPath, outPath, pw, cfg); err != nil {
				t.Errorf("Worker %d encryption failed: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestSaltCacheCleanup(t *testing.T) {
	// This is a bit tricky to test reliably with real time,
	// but we can at least ensure adding to the cache works and map operations are safe.
	// The actual expiration runs in a goroutine sleeping for an hour.
	// We won't wait for an hour, but we will check immediate existence.

	saltHex := "deadbeef"
	saltMu.Lock()
	saltCache[saltHex] = []byte{0xde, 0xad, 0xbe, 0xef}
	saltMu.Unlock()

	saltMu.RLock()
	_, exists := saltCache[saltHex]
	saltMu.RUnlock()
	if !exists {
		t.Error("Salt should exist in cache")
	}
	saltMu.Lock()
	delete(saltCache, saltHex)
	saltMu.Unlock()

	saltMu.RLock()
	_, existsAfter := saltCache[saltHex]
	saltMu.RUnlock()
	if existsAfter {
		t.Error("Salt should be removed")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("Byte at index %d not zeroed", i)
		}
	}
}

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()
	f := filepath.Join(tempDir, "exists.txt")
	if fileExists(f) {
		t.Error("File should not exist yet")
	}
	os.WriteFile(f, []byte("hi"), 0600)
	if !fileExists(f) {
		t.Error("File should exist")
	}
}

func TestBuildEnhancedAAD(t *testing.T) {
	cfg := getTestConfig()
	header, _ := createHeader(cfg)

	// Seq 0
	aad1, err := buildEnhancedAAD(header, 0)
	if err != nil {
		t.Fatal(err)
	}
	aad2, err := buildEnhancedAAD(header, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(aad1, aad2) {
		t.Error("AAD should differ for different sequence numbers")
	}
	if len(aad1) < 46 {
		t.Error("AAD seems too short")
	}
}

func TestCreateHeader_Defaults(t *testing.T) {
	cfg := getTestConfig()
	h, err := createHeader(cfg)
	if err != nil {
		t.Fatalf("createHeader failed: %v", err)
	}
	if string(h.Magic[:]) != MagicNumber {
		t.Error("Wrong magic number")
	}
	if h.Version != FileVersion {
		t.Error("Wrong version")
	}
	if h.ArgonTime != cfg.KeyTime {
		t.Error("ArgonTime mismatch")
	}
}

func TestChunkSizeBoundaries(t *testing.T) {
	// Create file larger than chunk size
	tempDir := t.TempDir()
	data := make([]byte, 2048) // 2KB
	rand.Read(data)
	inputFile := createTempFile(t, tempDir, data)
	outputFile := filepath.Join(tempDir, "chunked.enc")
	decryptedFile := filepath.Join(tempDir, "restored_chunked.txt")

	cfg := getTestConfig()
	cfg.ChunkSize = 1024 // Exact split

	pw := getTestPassword()
	defer pw.Close()
	ctx := context.Background()
	if err := encryptFile(ctx, inputFile, outputFile, pw, cfg); err != nil {
		t.Fatal(err)
	}
	if err := decryptFile(ctx, outputFile, decryptedFile, pw.Bytes(), cfg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, decryptedFile), data) {
		t.Error("Data mismatch with small chunks")
	}
}

func TestMainHelp(t *testing.T) {
	// Save original args/stdout
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// We can't easily capture stdout without pipes, but we can ensure it doesn't panic
	// and exits with 1 (which we can't catch without exec, but we can call showHelp directly)
	showHelp()
}

func TestSaltValidationLogic(t *testing.T) {
	// Directly test the generation
	s, err := generateSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Bytes()) != 32 {
		t.Error("Salt size mismatch")
	}
	_, err = generateSalt(0)
	if err == nil {
		t.Error("Should fail for 0 salt size")
	}
}

func TestHexEncodingInSaltCache(t *testing.T) {
	// Verify the map key generation logic used in validateSaltUniqueness
	salt := []byte{0, 1, 2, 3}
	expectedKey := hex.EncodeToString(salt)

	saltMu.Lock()
	saltCache[expectedKey] = salt
	saltMu.Unlock()
	if err := validateSaltUniqueness(salt); err == nil {
		t.Error("Should detect existing salt via hex key")
	}
	saltMu.Lock()
	delete(saltCache, expectedKey)
	saltMu.Unlock()
}
