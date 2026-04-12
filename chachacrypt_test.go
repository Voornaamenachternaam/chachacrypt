package main

import (
	"runtime"
	"testing"
)

func TestRotationHeaderMACAfterFieldMutation(t *testing.T) {
	pw := []byte("CorrectHorseBatteryStaple!123")
	threads := uint8(runtime.NumCPU())
	if threads > maxThreadLimit {
		threads = maxThreadLimit
	}
	if threads < minArgonThreads {
		threads = minArgonThreads
	}
	hdr, encKey, macKey, err := prepareRotationKeys(pw, defaultArgonTime, defaultArgonMemory, threads)
	if err != nil {
		t.Fatalf("prepareRotationKeys failed: %v", err)
	}
	defer secureZero(encKey)
	defer secureZero(macKey)

	// Simulate rotate flow where caller sets fields after key prep.
	hdr.KeyVersion = 42
	hdr.ChunkSize = defaultChunkSize
	hdr.NonceSize = nonceSize

	mac, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		t.Fatalf("computeHeaderHMAC failed: %v", err)
	}
	copy(hdr.HeaderMAC[:], mac)

	expected, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		t.Fatalf("computeHeaderHMAC second call failed: %v", err)
	}
	if !secureCompare(expected, hdr.HeaderMAC[:]) {
		t.Fatal("header MAC does not match finalized header")
	}
}

func TestValidatePathComponentsRejectsParentTraversal(t *testing.T) {
	if err := validatePathComponents("a/../b"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}

func TestURLPathUnescapeRejectsBadEncoding(t *testing.T) {
	if _, err := urlPathUnescape("abc%GG"); err == nil {
		t.Fatal("expected invalid encoding to error")
	}
}
