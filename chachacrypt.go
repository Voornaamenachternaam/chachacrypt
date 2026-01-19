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

	"golang.org/x/crypto/hkdf"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
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

	nonceSize = chacha20poly1305.NonceSizeX // 24

	derivedKeyBytes = 64
	keySize         = 32

	reservedLen = 7

	maxNonceLen = 1024
	maxCTSize   = 16 << 20

	usageExit = 2
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
	lowArgonMemory  = 32 * 1024
	lowArgonThreads = 2
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

// zero overwrites the given byte slice and calls runtime.KeepAlive to avoid
// compiler optimization removing the writes.
func zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func die(err error) {
	// Minimalistic user-facing errors to avoid leaking internal details.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		fmt.Fprintln(os.Stderr, "Error: file access issue — check paths/permissions.")
	} else {
		fmt.Fprintln(os.Stderr, "Error: An unexpected error occurred.")
	}
	os.Exit(1)
}

func readPasswordPrompt(prompt string) []byte {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		die(err)
	}
	return pw
}

func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func validatePasswordStrength(pw []byte) error {
	if len(pw) < 12 { // Minimum length of 12 characters
		return errors.New("password too short (minimum 12 characters)")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range string(pw) {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", c):
			hasSpecial = true
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
		return errors.New("password must contain a mix of at least three character types (uppercase, lowercase, digits, special characters)")
	}

	// Optional: Check against common weak patterns (can be expanded)
	weakPatterns := []string{"password", "123456", "qwerty", "admin"}
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
	r := hkdf.New(sha256.New, master, nil, []byte("chachacrypt-enc-mac-v1"))
	enc := make([]byte, keySize)
	mac := make([]byte, keySize)
	if _, err := io.ReadFull(r, enc); err != nil {
		zero(enc)
		zero(mac)
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, mac); err != nil {
		zero(enc)
		zero(mac)
		return nil, nil, err
	}
	return enc, mac, nil
}

func computeHeaderHMAC(hdr *fileHeader, macKey []byte) ([]byte, error) {
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
	const minTime = 2
	const minMemory = 64 * 1024 // 64 MiB
	const minThreads = 1

	if t < minTime {
		return fmt.Errorf("Argon2 time too low (min %d)", minTime)
	}
	if mem < minMemory {
		return fmt.Errorf("Argon2 memory too low (min %d KiB)", minMemory)
	}
	maxThreads := uint8(runtime.NumCPU() * 2)
	if threads < minThreads || threads > maxThreads {
		return fmt.Errorf("Argon2 threads out of bounds (min %d max %d)", minThreads, maxThreads)
	}
	return nil
}

/*** Entropy check (best-effort) ***/

func checkMinEntropy(data []byte) error {
	if len(data) < 16 {
		return nil
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[int(b)]++
	}
	var entropy float64
	length := float64(len(data))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	// Heuristic threshold: 3 bits/byte (very conservative)
	if entropy < 3.0 {
		return fmt.Errorf("insufficient entropy: %.2f bits/byte", entropy)
	}
	return nil
}

/*** Path safety and atomic write ***/

// safeOutputPath resolves symlinks, cleans, and ensures output is within CWD unless allowAbsolute.
// It rejects null bytes and basic traversal after evaluation.
func safeOutputPath(out string, allowAbsolute bool) (string, error) {
	if out == "" {
		return "", errors.New("empty output path")
	}
	if strings.IndexByte(out, 0) != -1 {
		return "", errors.New("null byte in path")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks in path: %w", err)
	}
	abs = filepath.Clean(resolved)
	parts := strings.Split(abs, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return "", errors.New("directory traversal detected in path")
		}
	}
	if !allowAbsolute {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get cwd: %w", err)
		}
		// Ensure abs is within cwd (prefix match on canonical absolute paths)
		rel, rerr := filepath.Rel(cwd, abs)
		if rerr != nil {
			return "", fmt.Errorf("evaluate path: %w", rerr)
		}
		if strings.HasPrefix(rel, "..") {
			return "", errors.New("output path outside current working directory; use --allow-absolute")
		}
	}
	return abs, nil
}

// atomicWriteReplace writes to a secure temporary file (0600) and renames into place.
// It prefers creating the temp file in the final directory for atomic rename, but if
// final directory looks insecure (symlink or group/other writable) it falls back to os.TempDir().
func atomicWriteReplace(tempDir, finalPath string, writer func(*os.File) error, force bool) error {
	dir := tempDir
	if dir == "" {
		dir = filepath.Dir(finalPath)
	}
	// Check dir security: avoid symlink or group/other-writable directories.
	useFallbackTemp := false
	info, serr := os.Lstat(dir)
	if serr != nil {
		// if Lstat fails, fallback to system temp
		useFallbackTemp = true
	} else {
		if info.Mode()&os.ModeSymlink != 0 {
			useFallbackTemp = true
		}
		if info.Mode().Perm()&0o022 != 0 {
			// group or others writable
			useFallbackTemp = true
		}
	}
	if useFallbackTemp {
		dir = os.TempDir()
		fmt.Fprintln(os.Stderr, "Warning: target directory not suitable for secure temp files; using system temp dir")
	}

	tmpFile, err := os.CreateTemp(dir, "chachacrypt-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure restrictive permissions
	if chmodErr := tmpFile.Chmod(0o600); chmodErr != nil {
		// Attempt to clean up and return error
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("set temp mode: %w", chmodErr)
	}

	defer func() {
		if cerr := tmpFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close temp %s: %v\n", tmpPath, cerr)
		}
		if rerr := os.Remove(tmpPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp %s: %v\n", tmpPath, rerr)
		}
	}()

	if err = writer(tmpFile); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	dfd, dfdErr := os.OpenFile(filepath.Dir(finalPath), os.O_RDONLY, 0)
	if dfdErr == nil {
		if syncErr := dfd.Sync(); syncErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: directory sync failed: %v\n", syncErr)
		}
		_ = dfd.Close()
	}

	if _, statErr := os.Stat(finalPath); statErr == nil {
		if force {
			if remErr := os.Remove(finalPath); remErr != nil {
				return fmt.Errorf("remove existing dest: %w", remErr)
			}
		} else {
			return fmt.Errorf("destination exists: %s (use --force)", finalPath)
		}
	}

	// Finally rename into place
	if err = os.Rename(tmpPath, finalPath); err != nil {
		if linkErr, ok := err.(*os.LinkError); ok && linkErr.Op == "rename" && strings.Contains(linkErr.Err.Error(), "cross-device link") {
			fmt.Fprintf(os.Stderr, "Warning: cross-device move detected; falling back to non-atomic copy for %s -> %s\n", tmpPath, finalPath)
			src, rerr := os.Open(tmpPath)
			if rerr != nil {
				return fmt.Errorf("open temp for copy: %w", rerr)
			}
			defer src.Close()

			dst, werr := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if werr != nil {
				return fmt.Errorf("create dest for copy: %w", werr)
			}
			defer dst.Close()

			if _, cerr := io.Copy(dst, src); cerr != nil {
				return fmt.Errorf("copy temp to dest: %w", cerr)
			}
			return nil
		}
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}

/*** Chunk framing helpers ***/

func writeChunkFrame(w io.Writer, nonce, ct []byte) error {
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

// processOneEncrypt reads up to hdr.ChunkSize and processes partial final chunk correctly.
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
	// Accept partial read (io.ErrUnexpectedEOF) as valid final chunk if n>0.
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
	if entErr := checkMinEntropy(nonce); entErr != nil {
		return true, fmt.Errorf("nonce entropy failed: %w", entErr)
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}
	ct := aead.Seal(nil, nonce, buf[:n], aad)
	if err = writeChunkFrame(out, nonce, ct); err != nil {
		return true, err
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Wrote chunk %d (pt=%d ct=%d)\n", idx, n, len(ct))
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
	}
}

// processOneDecrypt reads a framed chunk and authenticates it.
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
	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return true, errors.New("decryption failed (wrong password or tampered chunk)")
	}
	if _, err := out.Write(pt); err != nil {
		return true, fmt.Errorf("write plaintext: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Read chunk %d (pt=%d)\n", idx, len(pt))
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
	}
}

// processOneRotate decrypts with old AEAD and re-encrypts with new AEAD.
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
	aadOld, err := buildAAD(origHdr, idx)
	if err != nil {
		return true, err
	}
	pt, err := oldAEAD.Open(nil, nonce, ct, aadOld)
	if err != nil {
		return true, fmt.Errorf("decrypt chunk failed idx=%d: %w", idx, err)
	}
	defer zero(pt)
	newNonce := make([]byte, newHdr.NonceSize)
	if _, err = io.ReadFull(rand.Reader, newNonce); err != nil {
		return true, fmt.Errorf("new nonce gen: %w", err)
	}
	if entErr := checkMinEntropy(newNonce); entErr != nil {
		return true, fmt.Errorf("new nonce entropy failed: %w", entErr)
	}
	aadNew, err := buildAAD(newHdr, idx)
	if err != nil {
		return true, err
	}
	newCt := newAEAD.Seal(nil, newNonce, pt, aadNew)
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
	// constant-time magic compare
	var magicCmp [magicLen]byte
	copy(magicCmp[:], []byte(MagicString))
	if !secureCompare(hdr.Magic[:], magicCmp[:]) {
		return errors.New("invalid magic")
	}
	if hdr.Version != fileVersion {
		return fmt.Errorf("unsupported version %d", hdr.Version)
	}
	if err := validateArgon2Params(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return fmt.Errorf("invalid argon2 params: %w", err)
	}
	if hdr.ChunkSize == 0 || hdr.ChunkSize > maxChunkSize {
		return errors.New("invalid chunk size in header")
	}
	if hdr.NonceSize != nonceSize {
		return fmt.Errorf("invalid nonce size in header: %d", hdr.NonceSize)
	}
	for _, b := range hdr.Reserved {
		if b != 0 {
			return errors.New("reserved bytes non-zero")
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
		return nil, nil, nil, fmt.Errorf("salt gen: %w", err)
	}
	if entErr := checkMinEntropy(hdr.Salt[:]); entErr != nil {
		return nil, nil, nil, fmt.Errorf("salt entropy check failed: %w", entErr)
	}
	master := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	// ensure master is zeroed on return from this helper
	defer zero(master)

	encKey, macKey, err := deriveEncAndMacKeys(master)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, fmt.Errorf("derive keys: %w", err)
	}
	mac, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, fmt.Errorf("compute header mac: %w", err)
	}
	copy(hdr.HeaderMAC[:], mac)
	return &hdr, encKey, macKey, nil
}

// deriveKeysFromPassword derives enc and mac keys from a header and password, zeroing master on return.
func deriveKeysFromPassword(password []byte, hdr *fileHeader) (encKey, macKey []byte, err error) {
	master := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer zero(master)
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
		return fmt.Errorf("stat input file: %w", err)
	}
	if info.Mode().Perm()&0o066 != 0 {
		return errors.New("input file has overly permissive permissions (e.g., group/other writable or readable)")
	}

	pw1 := readPasswordPrompt("Password: ")
	defer zero(pw1)
	if len(pw1) == 0 {
		return errors.New("empty password not allowed")
	}
	pw2 := readPasswordPrompt("Confirm password: ")
	defer zero(pw2)
	if !secureCompare(pw1, pw2) {
		return errors.New("passwords do not match")
	}
	if err := validatePasswordStrength(pw1); err != nil {
		return fmt.Errorf("weak password: %w", err)
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
	// ensure keys zeroed after use
	defer zero(encKey)
	defer zero(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return fmt.Errorf("init aead: %w", err)
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
		return fmt.Errorf("header validation failed: %w", err)
	}

	pw := readPasswordPrompt("Password: ")
	defer zero(pw)
	encKey, macKey, err := deriveKeysFromPassword(pw, &hdr)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}
	// zero keys when done
	defer zero(encKey)
	defer zero(macKey)

	expected, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		return fmt.Errorf("compute header mac: %w", err)
	}
	if !hmac.Equal(expected, hdr.HeaderMAC[:]) {
		return errors.New("wrong password or corrupted header")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("init aead: %w", err)
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
		return nil, nil, nil, fmt.Errorf("invalid Argon2 params for rotation: %w", err)
	}
	var hdr fileHeader
	copy(hdr.Magic[:], []byte(MagicString))
	hdr.Version = fileVersion
	hdr.Timestamp = time.Now().Unix()
	hdr.ArgonTime = newArgonTime
	hdr.ArgonMemory = newArgonMem
	hdr.ArgonThreads = newArgonThreads

	if _, err := io.ReadFull(rand.Reader, hdr.Salt[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("new salt: %w", err)
	}
	if entErr := checkMinEntropy(hdr.Salt[:]); entErr != nil {
		return nil, nil, nil, fmt.Errorf("new salt entropy failed: %w", entErr)
	}
	master := deriveMasterKeyArgon(pwNew, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer zero(master)

	encKey, macKey, err := deriveEncAndMacKeys(master)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, fmt.Errorf("derive keys (new): %w", err)
	}
	mac, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, fmt.Errorf("compute header mac (new): %w", err)
	}
	copy(hdr.HeaderMAC[:], mac)
	return &hdr, encKey, macKey, nil
}

// rotateFile validates the old header, authenticates with old password, prompts new password,
// builds new header/keys and performs rotateChunks to produce a re-encrypted file.
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
		return fmt.Errorf("original header validation failed: %w", err)
	}

	pwOld := readPasswordPrompt("Current password: ")
	defer zero(pwOld)
	oldEncKey, oldMacKey, err := deriveKeysFromPassword(pwOld, &origHdr)
	if err != nil {
		return fmt.Errorf("derive keys (old): %w", err)
	}
	defer zero(oldEncKey)
	defer zero(oldMacKey)

	expected, err := computeHeaderHMAC(&origHdr, oldMacKey)
	if err != nil {
		return fmt.Errorf("compute header mac (old): %w", err)
	}
	if !hmac.Equal(expected, origHdr.HeaderMAC[:]) {
		return errors.New("wrong password or corrupted header (old)")
	}

	pwNew1 := readPasswordPrompt("New password: ")
	defer zero(pwNew1)
	if len(pwNew1) == 0 {
		return errors.New("empty new password not allowed")
	}
	pwNew2 := readPasswordPrompt("Confirm new password: ")
	defer zero(pwNew2)
	if !secureCompare(pwNew1, pwNew2) {
		return errors.New("passwords do not match")
	}
	if err := validatePasswordStrength(pwNew1); err != nil {
		return fmt.Errorf("weak new password: %w", err)
	}

	newHdr, newEncKey, newMacKey, err := prepareRotationKeys(pwNew1, newArgonTime, newArgonMem, newArgonThreads)
	if err != nil {
		return err
	}
	newHdr.KeyVersion = newKeyVersion
	newHdr.ChunkSize = origHdr.ChunkSize
	newHdr.NonceSize = origHdr.NonceSize
	// zero(new password handled by defer above)

	defer zero(newEncKey)
	defer zero(newMacKey)

	oldAEAD, err := chacha20poly1305.NewX(oldEncKey)
	if err != nil {
		return fmt.Errorf("init old aead: %w", err)
	}
	newAEAD, err := chacha20poly1305.NewX(newEncKey)
	if err != nil {
		return fmt.Errorf("init new aead: %w", err)
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
	fmt.Fprintf(os.Stderr, `Usage:
  chachacrypt -e infile outfile   # encrypt
  chachacrypt -d infile outfile   # decrypt
  chachacrypt -r infile outfile   # rotate (re-encrypt with new password/params)

Options:
`)
	flag.PrintDefaults()
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
		return 0, 0, 0, fmt.Errorf("unknown preset: %s", preset)
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
	enc := flag.Bool("e", false, "encrypt")
	dec := flag.Bool("d", false, "decrypt")
	rot := flag.Bool("r", false, "rotate (re-encrypt with new password/params)")
	force := flag.Bool("force", false, "overwrite output if exists")
	allowAbs := flag.Bool("allow-absolute", false, "allow writing output outside current working directory")
	chunkSizeFlag := flag.Uint(
		"chunk-size",
		defaultChunkSize,
		fmt.Sprintf("chunk size in bytes (max %d)", maxChunkSize),
	)
	preset := flag.String("preset", "default", "argon preset: default | high | low")
	argonTimeFlag := flag.Uint("argon-time", 0, "override argon time (optional)")
	argonMemFlag := flag.Uint("argon-memory", 0, "override argon memory (KiB) (optional)")
	argonThreadsFlag := flag.Uint("argon-threads", 0, "override argon threads (optional)")
	keyVersionFlag := flag.Uint("key-version", 1, "key version to write into header (rotate/encrypt)")
	verbose := flag.Bool("v", false, "verbose progress output")
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
	absIn, err := filepath.Abs(cfg.in)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	absOut, err := safeOutputPath(cfg.out, cfg.allowAbsolute)
	if err != nil {
		return err
	}
	// If output exists, ensure it's not same file as input
	inStat, err := os.Stat(absIn)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	if outStat, err := os.Stat(absOut); err == nil {
		if os.SameFile(inStat, outStat) {
			return errors.New("input and output are the same file; this is not allowed to prevent data loss")
		}
	}
	if cfg.chunkSize == 0 || cfg.chunkSize > maxChunkSize {
		return fmt.Errorf("invalid chunk size, must be 1..%d", maxChunkSize)
	}

	if cfg.enc {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Encrypting %s -> %s ...\n", absIn, absOut)
			fmt.Fprintf(
				os.Stderr,
				"Argon2: time=%d memory=%d KiB threads=%d chunk=%d\n",
				cfg.argTime,
				cfg.argMem,
				cfg.argThreads,
				cfg.chunkSize,
			)
		}
		return encryptFile(
			ctx,
			absIn,
			absOut,
			cfg.force,
			cfg.chunkSize,
			cfg.argTime,
			cfg.argMem,
			cfg.argThreads,
			cfg.keyVersion,
			cfg.verbose,
		)
	}
	if cfg.dec {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Decrypting %s -> %s ...\n", absIn, absOut)
		}
		return decryptFile(ctx, absIn, absOut, cfg.force, cfg.verbose)
	}
	if cfg.rot {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Rotating %s -> %s ...\n", absIn, absOut)
			fmt.Fprintf(
				os.Stderr,
				"New Argon2: time=%d memory=%d KiB threads=%d\n",
				cfg.argTime,
				cfg.argMem,
				cfg.argThreads,
			)
		}
		return rotateFile(
			ctx,
			absIn,
			absOut,
			cfg.force,
			cfg.argTime,
			cfg.argMem,
			cfg.argThreads,
			cfg.keyVersion,
			cfg.verbose,
		)
	}
	return nil
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
		fmt.Fprintln(os.Stderr, "interrupt - cancelling")
		cancel()
	}()

	start := time.Now()
	if err := runOperation(ctx, cfg); err != nil {
		die(err)
	}

	if atomic.LoadInt32(&cancelled) == 1 {
		die(errors.New("operation cancelled"))
	}

	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "Done in %s (goos=%s goarch=%s)\n", time.Since(start), runtime.GOOS, runtime.GOARCH)
	}
}
