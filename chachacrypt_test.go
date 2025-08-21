// chachacrypt_test.go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "plain.txt")
	outEnc := filepath.Join(tmpDir, "enc.cch")
	outDec := filepath.Join(tmpDir, "dec.txt")

	plain := []byte("The quick brown fox jumps over the lazy dog")
	if err := os.WriteFile(inPath, plain, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	pw := []byte("test-password-1234")
	opt := encryptOptions{
		Time:       1,
		MemoryKB:   32 * 1024,
		Threads:    1,
		ChunkBytes: 64,
	}
	if err := encryptFileAtomic(inPath, outEnc, pw, opt); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err := decryptFileAtomic(outEnc, outDec, pw); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	got, err := os.ReadFile(outDec)
	if err != nil {
		t.Fatalf("read dec: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", string(got), string(plain))
	}
}

func TestWrongPasswordFails(t *testing.T) {
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "plain.txt")
	outEnc := filepath.Join(tmpDir, "enc.cch")
	outDec := filepath.Join(tmpDir, "dec.txt")

	plain := []byte("hello world")
	if err := os.WriteFile(inPath, plain, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	pw := []byte("correct-password")
	opt := encryptOptions{
		Time:       1,
		MemoryKB:   32 * 1024,
		Threads:    1,
		ChunkBytes: 64,
	}
	if err := encryptFileAtomic(inPath, outEnc, pw, opt); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err := decryptFileAtomic(outEnc, outDec, []byte("wrong-password")); err == nil {
		t.Fatalf("decrypt succeeded with wrong password; expected failure")
	}
}

func TestCorruptedFileFails(t *testing.T) {
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "plain.txt")
	outEnc := filepath.Join(tmpDir, "enc.cch")
	outDec := filepath.Join(tmpDir, "dec.txt")

	plain := []byte("data for corruption test")
	if err := os.WriteFile(inPath, plain, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	pw := []byte("pw")
	opt := encryptOptions{
		Time:       1,
		MemoryKB:   32 * 1024,
		Threads:    1,
		ChunkBytes: 64,
	}
	if err := encryptFileAtomic(inPath, outEnc, pw, opt); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	// Corrupt a byte near the end of the file
	f, err := os.OpenFile(outEnc, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open for corrupt: %v", err)
	}
	stat, _ := f.Stat()
	if stat.Size() > 40 {
		if _, err := f.WriteAt([]byte{0xFF}, stat.Size()-40); err != nil {
			t.Fatalf("writeat: %v", err)
		}
	}
	_ = f.Close()
	if err := decryptFileAtomic(outEnc, outDec, pw); err == nil {
		t.Fatalf("decrypt succeeded on corrupted file; expected failure")
	}
}
