// Package main implements a secure file-encryption CLI.
// - Argon2id for KDF (golang.org/x/crypto/argon2.IDKey)
// - HKDF-SHA256 for key derivation (golang.org/x/crypto/hkdf)
// - XChaCha20-Poly1305 AEAD per-chunk (golang.org/x/crypto/chacha20poly1305)
// - Canonical header authenticated with HMAC-SHA256
// - Chunk framing with 4-byte BE length fields
//
// Targets Go 1.25.6 and uses only the modules pinned in go.mod.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

/*** Constants & presets ***/

const (
	MagicString = "CHACRYPT"
	magicLen    = 8

	fileVersion = uint16(1)

	saltSize = 32

	headerMACSize = 32

	defaultChunkSize = 1 << 20  // 1 MiB
	maxChunkSize     = 16 << 20 // 16 MiB
	minChunkSize     = 4096     // 4 KiB minimum

	nonceSize = chacha20poly1305.NonceSizeX // 24

	derivedKeyBytes = 64
	keySize         = 32

	reservedLen = 7

	maxNonceLen = 1024
	maxCTSize   = 16 << 20

	usageExit = 2

	// Security constants.
	minPasswordLength = 12
	maxPasswordLength = 1024
	zeroPassCount     = 3 // Number of times to overwrite sensitive memory

	// Platform-specific secure permissions.
	secureFilePerms = 0o600 // Owner read/write only
	secureDirPerms  = 0o700 // Owner rwx only
)

const headerTotalSize = magicLen + 2 + 4 + 8 + 4 + 4 + 1 + saltSize + 4 + 2 + reservedLen + headerMACSize

func init() {
	if hb, _ := serializeHeaderCanonical(&fileHeader{}); len(hb) != headerTotalSize {
		panic(fmt.Sprintf("headerTotalSize mismatch: got %d, want %d", len(hb), headerTotalSize))
	}
}

// Argon2 presets (memory in KiB).
const (
	defaultArgonTime    = 3
	defaultArgonMemory  = 128 * 1024
	defaultArgonThreads = 4

	highArgonTime    = 4
	highArgonMemory  = 256 * 1024
	highArgonThreads = 4

	lowArgonTime    = 2
	lowArgonMemory  = 64 * 1024 // Increased from 32*1024 for better security
	lowArgonThreads = 2

	// Validation bounds.
	minArgonTime    = 2
	minArgonMemory  = 64 * 1024   // 64 MiB minimum
	maxArgonMemory  = 1024 * 1024 // 1 GiB maximum
	minArgonThreads = 1
)

/*** Types ***/

type fileHeader struct {
	Timestamp    int64
	KeyVersion   uint32
	ArgonTime    uint32
	ArgonMemory  uint32
	ChunkSize    uint32
	Version      uint16
	NonceSize    uint16
	Salt         [saltSize]byte
	HeaderMAC    [headerMACSize]byte
	Magic        [magicLen]byte
	Reserved     [reservedLen]byte
	ArgonThreads uint8
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

/*** Utilities ***/

// secureZero overwrites the given byte slice multiple times with different patterns
// to prevent recovery via memory analysis. Uses runtime.KeepAlive to prevent
// compiler optimization.
func secureZero(b []byte) {
	if b == nil || len(b) == 0 {
		return
	}
	// First pass: all zeros
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)

	// Second pass: all ones
	for i := range b {
		b[i] = 0xFF
	}
	runtime.KeepAlive(b)

	// Final pass: zeros again
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// zero is a simpler version for non-critical cleanup.
func zero(b []byte) {
	if b == nil || len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func die(err error) {
	if err == nil {
		return
	}
	// Minimalistic user-facing errors to avoid leaking internal details.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		fmt.Fprintln(os.Stderr, "Error: file access issue — check paths/permissions.")
	} else if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Error: operation cancelled.")
	} else {
		fmt.Fprintln(os.Stderr, "Error: An unexpected error occurred.")
	}
	os.Exit(1)
}

func readPasswordPrompt(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("password read failed: %w", err)
	}
	if len(pw) == 0 {
		return nil, errors.New("empty password")
	}
	if len(pw) > maxPasswordLength {
		secureZero(pw)
		return nil, fmt.Errorf("password too long (max %d bytes)", maxPasswordLength)
	}
	return pw, nil
}

func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func validatePasswordStrength(pw []byte) error {
	if len(pw) < minPasswordLength {
		return fmt.Errorf("password too short (minimum %d characters)", minPasswordLength)
	}
	if len(pw) > maxPasswordLength {
		return fmt.Errorf("password too long (maximum %d characters)", maxPasswordLength)
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	consecutiveCount := 0
	var lastChar rune

	for _, c := range string(pw) {
		// Check for null bytes
		if c == 0 {
			return errors.New("password contains null byte")
		}

		// Check character types
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\", c):
			hasSpecial = true
		}

		// Check for excessive repetition
		if c == lastChar {
			consecutiveCount++
			if consecutiveCount >= 4 {
				return errors.New("password contains too many consecutive identical characters")
			}
		} else {
			consecutiveCount = 1
			lastChar = c
		}
	}

	// Require at least 3 out of 4 character types
	charTypeCount := 0
	if hasUpper {
		charTypeCount++
	}
	if hasLower {
		charTypeCount++
	}
	if hasDigit {
		charTypeCount++
	}
	if hasSpecial {
		charTypeCount++
	}

	if charTypeCount < 3 {
		return errors.New(
			"password must contain at least three types: uppercase, lowercase, digits, or special characters",
		)
	}

	// Check against common weak patterns
	weakPatterns := []string{
		"password", "123456", "qwerty", "admin", "letmein",
		"welcome", "monkey", "dragon", "master", "sunshine",
		"princess", "abc123", "111111", "000000",
	}
	lowerPw := strings.ToLower(string(pw))
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerPw, pattern) {
			return errors.New("password contains a common weak pattern")
		}
	}

	return nil
}

/*** Header serialization & AAD ***/

func serializeHeaderCanonical(hdr *fileHeader) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(hdr.Magic[:]); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.KeyVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.ArgonTime); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.ArgonMemory); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(hdr.ArgonThreads); err != nil {
		return nil, err
	}
	if _, err := buf.Write(hdr.Salt[:]); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.ChunkSize); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr.NonceSize); err != nil {
		return nil, err
	}
	if _, err := buf.Write(hdr.Reserved[:]); err != nil {
		return nil, err
	}
	if _, err := buf.Write(hdr.HeaderMAC[:]); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serializeHeaderForMAC returns the canonical header bytes with HeaderMAC zeroed.
func serializeHeaderForMAC(hdr *fileHeader) ([]byte, error) {
	tmp := *hdr
	clear(tmp.HeaderMAC[:])
	return serializeHeaderCanonical(&tmp)
}

func buildAAD(hdr *fileHeader, chunkIndex uint64) ([]byte, error) {
	hb, err := serializeHeaderCanonical(hdr)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(hb)
	if err := binary.Write(&b, binary.BigEndian, chunkIndex); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

/*** KDF and derived keys ***/

func deriveMasterKeyArgon(password, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, t, mem, threads, derivedKeyBytes)
}

func deriveEncAndMacKeys(master []byte) ([]byte, []byte, error) {
	if len(master) != derivedKeyBytes {
		return nil, nil, errors.New("invalid master key length")
	}

	r := hkdf.New(sha256.New, master, nil, []byte("chachacrypt-enc-mac-v1"))
	enc := make([]byte, keySize)
	mac := make([]byte, keySize)

	if _, err := io.ReadFull(r, enc); err != nil {
		secureZero(enc)
		secureZero(mac)
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, mac); err != nil {
		secureZero(enc)
		secureZero(mac)
		return nil, nil, err
	}
	return enc, mac, nil
}

func computeHeaderHMAC(hdr *fileHeader, macKey []byte) ([]byte, error) {
	if len(macKey) != keySize {
		return nil, errors.New("invalid MAC key length")
	}

	b, err := serializeHeaderForMAC(hdr)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, macKey)
	if _, err := m.Write(b); err != nil {
		return nil, err
	}
	return m.Sum(nil), nil
}

/*** Argon2 param validation ***/

func validateArgon2Params(t, mem uint32, threads uint8) error {
	if t < minArgonTime {
		return fmt.Errorf("Argon2 time too low (min %d)", minArgonTime)
	}
	if t > 100 {
		return errors.New("Argon2 time too high (max 100)")
	}
	if mem < minArgonMemory {
		return fmt.Errorf("Argon2 memory too low (min %d KiB)", minArgonMemory)
	}
	if mem > maxArgonMemory {
		return fmt.Errorf("Argon2 memory too high (max %d KiB)", maxArgonMemory)
	}
	maxThreads := uint8(runtime.NumCPU())
	if maxThreads > 64 {
		maxThreads = 64 // Reasonable upper bound
	}
	if threads < minArgonThreads || threads > maxThreads {
		return fmt.Errorf("Argon2 threads out of bounds (min %d max %d)", minArgonThreads, maxThreads)
	}
	return nil
}

/*** Entropy check (best-effort) ***/

func checkMinEntropy(data []byte) error {
	if len(data) < 16 {
		return errors.New("data too short for entropy check")
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[int(b)]++
	}

	var entropy float64
	length := float64(len(data))
	nonZeroCount := 0

	for _, c := range freq {
		if c == 0 {
			continue
		}
		nonZeroCount++
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}

	// Require good distribution of byte values
	if nonZeroCount < 128 {
		return fmt.Errorf("insufficient byte diversity: only %d/256 values present", nonZeroCount)
	}

	// Heuristic threshold: 7.5 bits/byte (truly random is ~8)
	const minEntropy = 7.5
	if entropy < minEntropy {
		return fmt.Errorf("insufficient entropy: %.2f bits/byte (min %.2f)", entropy, minEntropy)
	}

	return nil
}

// validateRandomness ensures crypto/rand is working properly.
func validateRandomness() error {
	test := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, test); err != nil {
		return fmt.Errorf("random number generator failure: %w", err)
	}
	defer zero(test)

	return checkMinEntropy(test)
}

/*** Path safety and atomic write ***/

// safeOutputPath resolves symlinks, cleans, and ensures output is secure.
func safeOutputPath(out string, allowAbsolute bool) (string, error) {
	// Basic validation
	if out == "" {
		return "", errors.New("empty output path")
	}
	if len(out) > 4096 {
		return "", errors.New("path too long")
	}
	if strings.IndexByte(out, 0) != -1 {
		return "", errors.New("null byte in path")
	}

	// Check for suspicious patterns
	suspicious := []string{"//", "\\\\", "/../", "\\..\\"}
	for _, pattern := range suspicious {
		if strings.Contains(out, pattern) {
			return "", errors.New("suspicious path pattern detected")
		}
	}

	// Normalize path separators
	normalized := filepath.FromSlash(out)

	// Get absolute path first to handle relative paths correctly
	abs, err := filepath.Abs(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Resolve symlinks after getting absolute path
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the file doesn't exist yet, EvalSymlinks will fail
		// In this case, resolve the parent directory
		parent := filepath.Dir(abs)
		resolvedParent, pErr := filepath.EvalSymlinks(parent)
		if pErr != nil {
			return "", fmt.Errorf("failed to resolve parent directory: %w", pErr)
		}
		resolved = filepath.Join(resolvedParent, filepath.Base(abs))
	}

	// Clean the resolved path
	clean := filepath.Clean(resolved)

	if !allowAbsolute {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		rel, err := filepath.Rel(cwd, clean)
		if err != nil {
			return "", fmt.Errorf("failed to compute relative path: %w", err)
		}
		if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
			return "", errors.New("output path is outside working directory")
		}
	}

	// Validate path components
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return "", errors.New("path contains parent directory reference")
		}
		if len(p) == 0 || p == "." {
			continue
		}
		if len(p) > 255 {
			return "", errors.New("path component too long")
		}
		// Check for control characters
		for _, c := range p {
			if c < 32 || c == 127 {
				return "", errors.New("path contains control characters")
			}
		}
	}

	return clean, nil
}

// setSecurePermissions sets platform-appropriate secure permissions.
func setSecurePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// On Windows, rely on NTFS permissions set during CreateTemp
		return nil
	}

	// On Unix-like systems, ensure 0600
	if info.Mode().Perm() != secureFilePerms {
		if err := os.Chmod(path, secureFilePerms); err != nil {
			return fmt.Errorf("failed to set secure permissions: %w", err)
		}
	}
	return nil
}

// atomicWriteReplace writes to a secure temporary file and renames into place.
func atomicWriteReplace(tempDir, finalPath string, writer func(*os.File) error, force bool) error {
	dir := tempDir
	if dir == "" {
		dir = filepath.Dir(finalPath)
	}

	// Check dir security
	useFallbackTemp := false
	info, serr := os.Lstat(dir)
	if serr != nil {
		useFallbackTemp = true
	} else {
		if info.Mode()&os.ModeSymlink != 0 {
			useFallbackTemp = true
		}
		// On Unix systems, check for group/other writable
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			useFallbackTemp = true
		}
	}

	if useFallbackTemp {
		dir = os.TempDir()
		fmt.Fprintln(os.Stderr, "Warning: using system temp directory for security")
	}

	tmpFile, err := os.CreateTemp(dir, ".chachacrypt-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Set restrictive permissions immediately
	if err := setSecurePermissions(tmpPath); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}

	var writeErr error
	defer func() {
		tmpFile.Close()
		if writeErr != nil || !force {
			os.Remove(tmpPath)
		}
	}()

	if writeErr = writer(tmpFile); writeErr != nil {
		return fmt.Errorf("write temp: %w", writeErr)
	}
	if writeErr = tmpFile.Sync(); writeErr != nil {
		return fmt.Errorf("sync temp: %w", writeErr)
	}
	if writeErr = tmpFile.Close(); writeErr != nil {
		return fmt.Errorf("close temp: %w", writeErr)
	}

	// Sync parent directory on Unix systems
	if runtime.GOOS != "windows" {
		if dfd, dfdErr := os.OpenFile(filepath.Dir(finalPath), os.O_RDONLY, 0); dfdErr == nil {
			dfd.Sync()
			dfd.Close()
		}
	}

	// Check if destination exists
	if _, statErr := os.Stat(finalPath); statErr == nil {
		if !force {
			return fmt.Errorf("destination exists: %s (use --force)", finalPath)
		}
		// Securely remove existing file
		if remErr := os.Remove(finalPath); remErr != nil {
			return fmt.Errorf("remove existing dest: %w", remErr)
		}
	}

	// Attempt atomic rename
	if err = os.Rename(tmpPath, finalPath); err != nil {
		linkErr := &os.LinkError{}
		if errors.As(err, &linkErr) {
			// Cross-device, fallback to copy
			fmt.Fprintf(os.Stderr, "Warning: cross-device move, using copy for %s\n", finalPath)

			src, rerr := os.Open(tmpPath)
			if rerr != nil {
				return fmt.Errorf("open temp for copy: %w", rerr)
			}
			defer src.Close()

			dst, werr := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, secureFilePerms)
			if werr != nil {
				return fmt.Errorf("create dest for copy: %w", werr)
			}
			defer dst.Close()

			if _, cerr := io.Copy(dst, src); cerr != nil {
				return fmt.Errorf("copy temp to dest: %w", cerr)
			}
			if serr := dst.Sync(); serr != nil {
				return fmt.Errorf("sync dest: %w", serr)
			}

			// Remove temp file after successful copy
			os.Remove(tmpPath)
			return nil
		}
		return fmt.Errorf("rename temp: %w", err)
	}

	// Final permission check
	return setSecurePermissions(finalPath)
}

/*** Chunk framing helpers ***/

func writeChunkFrame(w io.Writer, nonce, ct []byte) error {
	if len(nonce) == 0 || len(nonce) > maxNonceLen {
		return fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	if len(ct) > maxCTSize {
		return fmt.Errorf("ciphertext too large: %d", len(ct))
	}

	if err := binary.Write(w, binary.BigEndian, uint32(len(nonce))); err != nil {
		return fmt.Errorf("write nonce len: %w", err)
	}
	if _, err := w.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(ct))); err != nil {
		return fmt.Errorf("write ct len: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return fmt.Errorf("write ct: %w", err)
	}
	return nil
}

func readChunkFrame(r io.Reader) ([]byte, []byte, error) {
	var nNonce uint32
	if err := binary.Read(r, binary.BigEndian, &nNonce); err != nil {
		return nil, nil, err
	}
	if nNonce == 0 || nNonce > maxNonceLen {
		return nil, nil, fmt.Errorf("invalid nonce length: %d", nNonce)
	}

	nonce := make([]byte, nNonce)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}

	var nCT uint32
	if err := binary.Read(r, binary.BigEndian, &nCT); err != nil {
		return nil, nil, fmt.Errorf("read ct len: %w", err)
	}
	if nCT > maxCTSize {
		return nil, nil, fmt.Errorf("ciphertext too large: %d", nCT)
	}

	ct := make([]byte, nCT)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, nil, fmt.Errorf("read ct: %w", err)
	}

	return nonce, ct, nil
}

/*** Chunk processors ***/

func processOneEncrypt(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipherAEAD,
	buf []byte,
	idx uint64,
	verbose bool,
) (bool, error) {
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}

	n, rerr := io.ReadFull(in, buf)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return true, fmt.Errorf("read input: %w", rerr)
	}
	if n == 0 && rerr == io.EOF {
		return true, nil
	}

	nonce := make([]byte, hdr.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return true, fmt.Errorf("nonce gen: %w", err)
	}
	defer zero(nonce)

	if entErr := checkMinEntropy(nonce); entErr != nil {
		return true, fmt.Errorf("nonce entropy failed: %w", entErr)
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	ct := aead.Seal(nil, nonce, buf[:n], aad)
	if err = writeChunkFrame(out, nonce, ct); err != nil {
		zero(ct)
		return true, err
	}
	zero(ct)

	if verbose {
		fmt.Fprintf(os.Stderr, "Encrypted chunk %d (pt=%d ct=%d)\n", idx, n, len(ct))
	}

	if n < int(hdr.ChunkSize) {
		return true, nil
	}
	return false, nil
}

func encryptChunks(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipherAEAD,
	verbose bool,
) error {
	buf := make([]byte, hdr.ChunkSize)
	defer zero(buf)

	var idx uint64
	for {
		done, err := processOneEncrypt(ctx, in, out, hdr, aead, buf, idx, verbose)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		idx++
		if idx == 0 {
			return errors.New("chunk index overflow")
		}
	}
}

func processOneDecrypt(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipherAEAD,
	idx uint64,
	verbose bool,
) (bool, error) {
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}

	nonce, ct, rerr := readChunkFrame(in)
	if rerr != nil {
		if errors.Is(rerr, io.EOF) {
			return true, nil
		}
		return true, rerr
	}
	defer zero(nonce)
	defer zero(ct)

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return true, errors.New("authentication failed: wrong password or corrupted data")
	}
	defer zero(pt)

	if _, err := out.Write(pt); err != nil {
		return true, fmt.Errorf("write plaintext: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Decrypted chunk %d (pt=%d)\n", idx, len(pt))
	}
	return false, nil
}

func decryptChunks(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipherAEAD,
	verbose bool,
) error {
	var idx uint64
	for {
		done, err := processOneDecrypt(ctx, in, out, hdr, aead, idx, verbose)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		idx++
		if idx == 0 {
			return errors.New("chunk index overflow")
		}
	}
}

func processOneRotate(
	ctx context.Context,
	in io.ReadSeeker,
	out io.Writer,
	origHdr *fileHeader,
	oldAEAD cipherAEAD,
	newHdr *fileHeader,
	newAEAD cipherAEAD,
	idx uint64,
	verbose bool,
) (bool, error) {
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}

	nonce, ct, rerr := readChunkFrame(in)
	if rerr != nil {
		if errors.Is(rerr, io.EOF) {
			return true, nil
		}
		return true, rerr
	}
	defer zero(nonce)
	defer zero(ct)

	aadOld, err := buildAAD(origHdr, idx)
	if err != nil {
		return true, err
	}

	pt, err := oldAEAD.Open(nil, nonce, ct, aadOld)
	if err != nil {
		return true, fmt.Errorf("decrypt chunk %d failed: authentication error", idx)
	}
	defer secureZero(pt)

	newNonce := make([]byte, newHdr.NonceSize)
	if _, err = io.ReadFull(rand.Reader, newNonce); err != nil {
		return true, fmt.Errorf("new nonce gen: %w", err)
	}
	defer zero(newNonce)

	if entErr := checkMinEntropy(newNonce); entErr != nil {
		return true, fmt.Errorf("new nonce entropy failed: %w", entErr)
	}

	aadNew, err := buildAAD(newHdr, idx)
	if err != nil {
		return true, err
	}

	newCt := newAEAD.Seal(nil, newNonce, pt, aadNew)
	defer zero(newCt)

	if err := writeChunkFrame(out, newNonce, newCt); err != nil {
		return true, err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Rotated chunk %d\n", idx)
	}
	return false, nil
}

func rotateChunks(
	ctx context.Context,
	in io.ReadSeeker,
	out io.Writer,
	origHdr *fileHeader,
	oldAEAD cipherAEAD,
	newHdr *fileHeader,
	newAEAD cipherAEAD,
	verbose bool,
) error {
	if _, err := in.Seek(int64(headerTotalSize), io.SeekStart); err != nil {
		return fmt.Errorf("seek input: %w", err)
	}

	var idx uint64
	for {
		done, err := processOneRotate(ctx, in, out, origHdr, oldAEAD, newHdr, newAEAD, idx, verbose)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		idx++
		if idx == 0 {
			return errors.New("chunk index overflow")
		}
	}
}

/*** Header parse and validation ***/

func parseHeaderFromBytes(data []byte, hdr *fileHeader) error {
	if len(data) < headerTotalSize {
		return errors.New("header too short")
	}

	buf := bytes.NewReader(data)
	if _, err := io.ReadFull(buf, hdr.Magic[:]); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.Version); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.KeyVersion); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.Timestamp); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.ArgonTime); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.ArgonMemory); err != nil {
		return err
	}
	b, err := buf.ReadByte()
	if err != nil {
		return err
	}
	hdr.ArgonThreads = b
	if _, err := io.ReadFull(buf, hdr.Salt[:]); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.ChunkSize); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &hdr.NonceSize); err != nil {
		return err
	}
	if _, err := io.ReadFull(buf, hdr.Reserved[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(buf, hdr.HeaderMAC[:]); err != nil {
		return err
	}
	return nil
}

func validateHeader(hdr *fileHeader) error {
	// Constant-time magic compare
	var magicCmp [magicLen]byte
	copy(magicCmp[:], []byte(MagicString))
	if !secureCompare(hdr.Magic[:], magicCmp[:]) {
		return errors.New("invalid file format")
	}

	if hdr.Version != fileVersion {
		return fmt.Errorf("unsupported version %d", hdr.Version)
	}

	// Validate timestamp is reasonable (not in far future)
	now := time.Now().Unix()
	if hdr.Timestamp > now+86400 {
		return errors.New("invalid timestamp: file from future")
	}
	if hdr.Timestamp < 0 {
		return errors.New("invalid timestamp: negative value")
	}

	if err := validateArgon2Params(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return fmt.Errorf("invalid argon2 params: %w", err)
	}

	if hdr.ChunkSize < minChunkSize || hdr.ChunkSize > maxChunkSize {
		return fmt.Errorf("invalid chunk size: %d (must be %d-%d)", hdr.ChunkSize, minChunkSize, maxChunkSize)
	}

	if hdr.NonceSize != nonceSize {
		return fmt.Errorf("invalid nonce size: %d (expected %d)", hdr.NonceSize, nonceSize)
	}

	// Reserved bytes must be zero
	for i, b := range hdr.Reserved {
		if b != 0 {
			return fmt.Errorf("reserved byte %d is non-zero", i)
		}
	}

	return nil
}

/*** High-level helpers for building headers and keys ***/

func buildHeaderAndKeysForEncrypt(
	password []byte,
	chunkSize uint32,
	argonTime, argonMem uint32,
	argonThreads uint8,
	keyVersion uint32,
) (*fileHeader, []byte, []byte, error) {
	if err := validateArgon2Params(argonTime, argonMem, argonThreads); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid Argon2 parameters: %w", err)
	}

	var hdr fileHeader
	copy(hdr.Magic[:], []byte(MagicString))
	hdr.Version = fileVersion
	hdr.KeyVersion = keyVersion
	hdr.Timestamp = time.Now().Unix()
	hdr.ArgonTime = argonTime
	hdr.ArgonMemory = argonMem
	hdr.ArgonThreads = argonThreads
	hdr.ChunkSize = chunkSize
	hdr.NonceSize = uint16(nonceSize)

	if _, err := io.ReadFull(rand.Reader, hdr.Salt[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("salt generation failed: %w", err)
	}
	if entErr := checkMinEntropy(hdr.Salt[:]); entErr != nil {
		return nil, nil, nil, fmt.Errorf("salt entropy check failed: %w", entErr)
	}

	master := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer secureZero(master)

	encKey, macKey, err := deriveEncAndMacKeys(master)
	if err != nil {
		secureZero(encKey)
		secureZero(macKey)
		return nil, nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	mac, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		secureZero(encKey)
		secureZero(macKey)
		return nil, nil, nil, fmt.Errorf("compute header mac: %w", err)
	}
	copy(hdr.HeaderMAC[:], mac)

	return &hdr, encKey, macKey, nil
}

func deriveKeysFromPassword(password []byte, hdr *fileHeader) (encKey, macKey []byte, err error) {
	master := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer secureZero(master)
	return deriveEncAndMacKeys(master)
}

/*** Encrypt / Decrypt / Rotate high-level operations ***/

func encryptFile(
	ctx context.Context,
	inPath, outPath string,
	force bool,
	chunkSize uint32,
	argonTime, argonMem uint32,
	argonThreads uint8,
	keyVersion uint32,
	verbose bool,
) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}

	// Security checks on input file
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("input file is writable by group or other (security risk)")
		}
	}
	if info.Size() < 0 {
		return errors.New("invalid file size")
	}

	pw1, err := readPasswordPrompt("Password: ")
	if err != nil {
		return err
	}
	defer secureZero(pw1)

	pw2, err := readPasswordPrompt("Confirm password: ")
	if err != nil {
		return err
	}
	defer secureZero(pw2)

	if !secureCompare(pw1, pw2) {
		return errors.New("passwords do not match")
	}
	if err := validatePasswordStrength(pw1); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	hdr, encKey, macKey, err := buildHeaderAndKeysForEncrypt(
		pw1,
		chunkSize,
		argonTime,
		argonMem,
		argonThreads,
		keyVersion,
	)
	if err != nil {
		return err
	}
	defer secureZero(encKey)
	defer secureZero(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}

	writer := func(f *os.File) error {
		hb, err := serializeHeaderCanonical(hdr)
		if err != nil {
			return fmt.Errorf("serialize header: %w", err)
		}
		if _, err := f.Write(hb); err != nil {
			return fmt.Errorf("write header: %w", err)
		}
		return encryptChunks(ctx, in, f, hdr, aead, verbose)
	}

	dir := filepath.Dir(outPath)
	return atomicWriteReplace(dir, outPath, writer, force)
}

func decryptFile(ctx context.Context, inPath, outPath string, force bool, verbose bool) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	hdrBytes := make([]byte, headerTotalSize)
	if _, err := io.ReadFull(in, hdrBytes); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	var hdr fileHeader
	if err := parseHeaderFromBytes(hdrBytes, &hdr); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	if err := validateHeader(&hdr); err != nil {
		return fmt.Errorf("header validation: %w", err)
	}

	pw, err := readPasswordPrompt("Password: ")
	if err != nil {
		return err
	}
	defer secureZero(pw)

	encKey, macKey, err := deriveKeysFromPassword(pw, &hdr)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}
	defer secureZero(encKey)
	defer secureZero(macKey)

	expected, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		return fmt.Errorf("compute header mac: %w", err)
	}
	if !hmac.Equal(expected, hdr.HeaderMAC[:]) {
		return errors.New("authentication failed: wrong password or corrupted file")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}

	writer := func(f *os.File) error {
		return decryptChunks(ctx, in, f, &hdr, aead, verbose)
	}

	dir := filepath.Dir(outPath)
	return atomicWriteReplace(dir, outPath, writer, force)
}

func prepareRotationKeys(
	pwNew []byte,
	newArgonTime, newArgonMem uint32,
	newArgonThreads uint8,
) (*fileHeader, []byte, []byte, error) {
	if err := validateArgon2Params(newArgonTime, newArgonMem, newArgonThreads); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid Argon2 params: %w", err)
	}

	var hdr fileHeader
	copy(hdr.Magic[:], []byte(MagicString))
	hdr.Version = fileVersion
	hdr.Timestamp = time.Now().Unix()
	hdr.ArgonTime = newArgonTime
	hdr.ArgonMemory = newArgonMem
	hdr.ArgonThreads = newArgonThreads

	if _, err := io.ReadFull(rand.Reader, hdr.Salt[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("new salt generation: %w", err)
	}
	if entErr := checkMinEntropy(hdr.Salt[:]); entErr != nil {
		return nil, nil, nil, fmt.Errorf("new salt entropy failed: %w", entErr)
	}

	master := deriveMasterKeyArgon(pwNew, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer secureZero(master)

	encKey, macKey, err := deriveEncAndMacKeys(master)
	if err != nil {
		secureZero(encKey)
		secureZero(macKey)
		return nil, nil, nil, fmt.Errorf("derive keys: %w", err)
	}

	mac, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		secureZero(encKey)
		secureZero(macKey)
		return nil, nil, nil, fmt.Errorf("compute header mac: %w", err)
	}
	copy(hdr.HeaderMAC[:], mac)

	return &hdr, encKey, macKey, nil
}

func rotateFile(
	ctx context.Context,
	inPath, outPath string,
	force bool,
	newArgonTime, newArgonMem uint32,
	newArgonThreads uint8,
	newKeyVersion uint32,
	verbose bool,
) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	hdrBytes := make([]byte, headerTotalSize)
	if _, err := io.ReadFull(in, hdrBytes); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	var origHdr fileHeader
	if err := parseHeaderFromBytes(hdrBytes, &origHdr); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	if err := validateHeader(&origHdr); err != nil {
		return fmt.Errorf("header validation: %w", err)
	}

	pwOld, err := readPasswordPrompt("Current password: ")
	if err != nil {
		return err
	}
	defer secureZero(pwOld)

	oldEncKey, oldMacKey, err := deriveKeysFromPassword(pwOld, &origHdr)
	if err != nil {
		return fmt.Errorf("derive old keys: %w", err)
	}
	defer secureZero(oldEncKey)
	defer secureZero(oldMacKey)

	expected, err := computeHeaderHMAC(&origHdr, oldMacKey)
	if err != nil {
		return fmt.Errorf("compute header mac: %w", err)
	}
	if !hmac.Equal(expected, origHdr.HeaderMAC[:]) {
		return errors.New("authentication failed: wrong password")
	}

	pwNew1, err := readPasswordPrompt("New password: ")
	if err != nil {
		return err
	}
	defer secureZero(pwNew1)

	pwNew2, err := readPasswordPrompt("Confirm new password: ")
	if err != nil {
		return err
	}
	defer secureZero(pwNew2)

	if !secureCompare(pwNew1, pwNew2) {
		return errors.New("new passwords do not match")
	}
	if err := validatePasswordStrength(pwNew1); err != nil {
		return fmt.Errorf("new password validation: %w", err)
	}

	newHdr, newEncKey, newMacKey, err := prepareRotationKeys(pwNew1, newArgonTime, newArgonMem, newArgonThreads)
	if err != nil {
		return err
	}
	newHdr.KeyVersion = newKeyVersion
	newHdr.ChunkSize = origHdr.ChunkSize
	newHdr.NonceSize = origHdr.NonceSize

	defer secureZero(newEncKey)
	defer secureZero(newMacKey)

	oldAEAD, err := chacha20poly1305.NewX(oldEncKey)
	if err != nil {
		return fmt.Errorf("init old cipher: %w", err)
	}
	newAEAD, err := chacha20poly1305.NewX(newEncKey)
	if err != nil {
		return fmt.Errorf("init new cipher: %w", err)
	}

	writer := func(f *os.File) error {
		hb, err := serializeHeaderCanonical(newHdr)
		if err != nil {
			return fmt.Errorf("serialize new header: %w", err)
		}
		if _, err := f.Write(hb); err != nil {
			return fmt.Errorf("write new header: %w", err)
		}
		return rotateChunks(ctx, in, f, &origHdr, oldAEAD, newHdr, newAEAD, verbose)
	}

	dir := filepath.Dir(outPath)
	return atomicWriteReplace(dir, outPath, writer, force)
}

/*** CLI + main ***/

func printUsage() {
	fmt.Fprintf(os.Stderr, `chachacrypt - Secure File Encryption Tool
Version 1.0.0 (Go 1.25.6)

Usage:
  chachacrypt -e infile outfile   # encrypt
  chachacrypt -d infile outfile   # decrypt
  chachacrypt -r infile outfile   # rotate (re-encrypt with new password/params)

Options:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nSecurity Features:\n")
	fmt.Fprintf(os.Stderr, "  - XChaCha20-Poly1305 authenticated encryption\n")
	fmt.Fprintf(os.Stderr, "  - Argon2id key derivation\n")
	fmt.Fprintf(os.Stderr, "  - Secure memory handling\n")
	fmt.Fprintf(os.Stderr, "  - Authenticated headers\n")
}

func parsePreset(preset string) (uint32, uint32, uint8, error) {
	switch strings.ToLower(preset) {
	case "", "default":
		return defaultArgonTime, defaultArgonMemory, defaultArgonThreads, nil
	case "high":
		return highArgonTime, highArgonMemory, highArgonThreads, nil
	case "low":
		return lowArgonTime, lowArgonMemory, lowArgonThreads, nil
	default:
		return 0, 0, 0, fmt.Errorf("unknown preset: %s (valid: default, high, low)", preset)
	}
}

type runConfig struct {
	in            string
	out           string
	argMem        uint32
	chunkSize     uint32
	argTime       uint32
	keyVersion    uint32
	rot           bool
	dec           bool
	force         bool
	allowAbsolute bool
	enc           bool
	argThreads    uint8
	verbose       bool
}

func parseFlags() (runConfig, error) {
	var cfg runConfig
	enc := flag.Bool("e", false, "encrypt mode")
	dec := flag.Bool("d", false, "decrypt mode")
	rot := flag.Bool("r", false, "rotate mode (re-encrypt with new password/params)")
	force := flag.Bool("force", false, "overwrite output if exists")
	allowAbs := flag.Bool("allow-absolute", false, "allow writing output outside current directory")
	chunkSizeFlag := flag.Uint(
		"chunk-size",
		defaultChunkSize,
		fmt.Sprintf("chunk size in bytes (%d-%d)", minChunkSize, maxChunkSize),
	)
	preset := flag.String("preset", "default", "argon preset: default | high | low")
	argonTimeFlag := flag.Uint("argon-time", 0, "override argon time iterations")
	argonMemFlag := flag.Uint("argon-memory", 0, "override argon memory (KiB)")
	argonThreadsFlag := flag.Uint("argon-threads", 0, "override argon threads")
	keyVersionFlag := flag.Uint("key-version", 1, "key version (for key rotation)")
	verbose := flag.Bool("v", false, "verbose output")
	flag.Parse()

	if (*enc && *dec) || (*dec && *rot) || (*enc && *rot) || (!*enc && !*dec && !*rot) || flag.NArg() != 2 {
		printUsage()
		return cfg, errors.New("invalid arguments")
	}

	cfg.enc = *enc
	cfg.dec = *dec
	cfg.rot = *rot
	cfg.force = *force
	cfg.allowAbsolute = *allowAbs
	cfg.chunkSize = uint32(*chunkSizeFlag)
	cfg.verbose = *verbose
	cfg.in = flag.Arg(0)
	cfg.out = flag.Arg(1)

	argTime, argMem, argThreads, err := parsePreset(*preset)
	if err != nil {
		return cfg, err
	}
	if *argonTimeFlag != 0 {
		argTime = uint32(*argonTimeFlag)
	}
	if *argonMemFlag != 0 {
		argMem = uint32(*argonMemFlag)
	}
	if *argonThreadsFlag != 0 {
		argThreads = uint8(*argonThreadsFlag)
	}

	if err := validateArgon2Params(argTime, argMem, argThreads); err != nil {
		return cfg, fmt.Errorf("invalid Argon2 configuration: %w", err)
	}

	cfg.argTime = argTime
	cfg.argMem = argMem
	cfg.argThreads = argThreads
	cfg.keyVersion = uint32(*keyVersionFlag)

	return cfg, nil
}

func runOperation(ctx context.Context, cfg runConfig) error {
	// Validate random number generator
	if err := validateRandomness(); err != nil {
		return fmt.Errorf("system entropy check failed: %w", err)
	}

	absIn, err := filepath.Abs(cfg.in)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}

	absOut, err := safeOutputPath(cfg.out, cfg.allowAbsolute)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Prevent same-file operations
	inStat, err := os.Stat(absIn)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	if outStat, err := os.Stat(absOut); err == nil {
		if os.SameFile(inStat, outStat) {
			return errors.New("input and output are the same file")
		}
	}

	if cfg.chunkSize < minChunkSize || cfg.chunkSize > maxChunkSize {
		return fmt.Errorf("invalid chunk size: %d (must be %d-%d)", cfg.chunkSize, minChunkSize, maxChunkSize)
	}

	if cfg.enc {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Encrypting: %s -> %s\n", absIn, absOut)
			fmt.Fprintf(
				os.Stderr,
				"Parameters: Argon2(t=%d,m=%d KiB,p=%d), chunk=%d\n",
				cfg.argTime, cfg.argMem, cfg.argThreads, cfg.chunkSize,
			)
		}
		return encryptFile(
			ctx, absIn, absOut, cfg.force,
			cfg.chunkSize, cfg.argTime, cfg.argMem, cfg.argThreads,
			cfg.keyVersion, cfg.verbose,
		)
	}

	if cfg.dec {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Decrypting: %s -> %s\n", absIn, absOut)
		}
		return decryptFile(ctx, absIn, absOut, cfg.force, cfg.verbose)
	}

	if cfg.rot {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Rotating: %s -> %s\n", absIn, absOut)
			fmt.Fprintf(
				os.Stderr,
				"New parameters: Argon2(t=%d,m=%d KiB,p=%d)\n",
				cfg.argTime, cfg.argMem, cfg.argThreads,
			)
		}
		return rotateFile(
			ctx, absIn, absOut, cfg.force,
			cfg.argTime, cfg.argMem, cfg.argThreads,
			cfg.keyVersion, cfg.verbose,
		)
	}

	return errors.New("no operation specified")
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		if err.Error() != "invalid arguments" {
			die(err)
		}
		os.Exit(usageExit)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var cancelled int32
	go func() {
		<-sigCh
		atomic.StoreInt32(&cancelled, 1)
		fmt.Fprintln(os.Stderr, "\nInterrupt received - cancelling operation...")
		cancel()
	}()

	start := time.Now()
	if err := runOperation(ctx, cfg); err != nil {
		die(err)
	}

	if atomic.LoadInt32(&cancelled) == 1 {
		die(errors.New("operation cancelled by user"))
	}

	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "Completed in %s (goos=%s goarch=%s)\n",
			time.Since(start), runtime.GOOS, runtime.GOARCH)
	}
}
