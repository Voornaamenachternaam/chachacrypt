// chachacrypt_test.go

package main

import (
    "bytes"
    "testing"
)

// Test buildEnhancedAAD with basic header and chunk indices.
func TestBuildEnhancedAAD(t *testing.T) {
    header := FileHeader{
        KeySize:   16,
        SaltSize:  8,
        ChunkSize: 1024,
        NonceSize: 24,
    }
    // Test with chunkIndex 0
    aad0 := buildEnhancedAAD(header, 0)
    if len(aad0) == 0 {
        t.Errorf("buildEnhancedAAD returned empty for chunkIndex 0")
    }
    // Test with chunkIndex 5
    aad5 := buildEnhancedAAD(header, 5)
    if bytes.Equal(aad0, aad5) {
        t.Errorf("AAD should differ for different chunkIndex")
    }
}

// Test deriveKey produces deterministic output length.
func TestDeriveKey(t *testing.T) {
    header := FileHeader{
        KeySize:   32,
        SaltSize:  16,
        ChunkSize: 2048,
        NonceSize: 24,
    }
    key := deriveKey(header, 32)
    if len(key) != 32 {
        t.Errorf("deriveKey returned key of length %d, expected 32", len(key))
    }
    // Same header should yield same key
    key2 := deriveKey(header, 32)
    if !bytes.Equal(key, key2) {
        t.Errorf("deriveKey not deterministic")
    }
    // Different header -> different key
    header2 := header
    header2.SaltSize = 17
    key3 := deriveKey(header2, 32)
    if bytes.Equal(key, key3) {
        t.Errorf("deriveKey should differ for different header")
    }
}

// Test writeAll by writing to a bytes buffer.
func TestWriteAll(t *testing.T) {
    buf := &bytes.Buffer{}
    data := []byte("Hello, world!")
    n, err := writeAll(buf, data)
    if err != nil {
        t.Fatalf("writeAll returned error: %v", err)
    }
    if n != len(data) {
        t.Errorf("writeAll wrote %d bytes, expected %d", n, len(data))
    }
    if buf.String() != string(data) {
        t.Errorf("Buffer has %q, expected %q", buf.String(), data)
    }
}
