package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
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
	"unicode/utf8"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"
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

	// Platform-specific secure permissions (not directly used on Windows).
	secureFilePerms = 0o600 // Owner read/write only on Unix
	secureDirPerms  = 0o700 // Owner rwx only on Unix
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
	Salt         [saltSize]byte
	HeaderMAC    [headerMACSize]byte
	Magic        [magicLen]byte
	KeyVersion   uint32
	ArgonTime    uint32
	ArgonMemory  uint32
	ChunkSize    uint32
	Version      uint16
	NonceSize    uint16
	ArgonThreads uint8
	Reserved     [reservedLen]byte
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

// clear is a lightweight zero for small fixed buffers (no multiple passes).
func clear(b []byte) {
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}

func readPasswordPrompt(prompt string) ([]byte, error) {
	// Ensure interactive terminal to avoid accidental logging in non-interactive contexts.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("password prompt requires an interactive terminal")
	}
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

// validatePasswordStrength checks password strength without making string copies of the password.
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
	var lastRune rune

	// Iterate over runes without converting to string
	for i := 0; i < len(pw); {
		r, size := utf8.DecodeRune(pw[i:])
		if r == utf8.RuneError && size == 1 {
			// treat as byte
			r = rune(pw[i])
			size = 1
		}
		if r == 0 {
			return errors.New("password contains null byte")
		}
		switch {
		case 'A' <= r && r <= 'Z':
			hasUpper = true
		case 'a' <= r && r <= 'z':
			hasLower = true
		case '0' <= r && r <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\", r):
			hasSpecial = true
		default:
			// other unicode categories count as "special"
			if r > 127 {
				hasSpecial = true
			}
		}
		if r == lastRune {
			consecutiveCount++
			if consecutiveCount >= 4 {
				return errors.New("password contains too many consecutive identical characters")
			}
		} else {
			consecutiveCount = 1
			lastRune = r
		}
		i += size
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

	// Check against common weak patterns using a lower-cased byte copy (ASCII-only).
	weakPatterns := [][]byte{
		[]byte("password"), []byte("123456"), []byte("qwerty"), []byte("admin"), []byte("letmein"),
		[]byte("welcome"), []byte("monkey"), []byte("dragon"), []byte("master"), []byte("sunshine"),
		[]byte("princess"), []byte("abc123"), []byte("111111"), []byte("000000"),
	}

	lowerPw := make([]byte, len(pw))
	for i := range pw {
		b := pw[i]
		if 'A' <= b && b <= 'Z' {
			lowerPw[i] = b + ('a' - 'A')
		} else {
			lowerPw[i] = b
		}
	}
	defer secureZero(lowerPw)

	for _, pat := range weakPatterns {
		// Constant-time contains check
		if bytesContains(lowerPw, pat) {
			return errors.New("password contains a common weak pattern")
		}
	}

	return nil
}

// bytesContains is a tiny helper to avoid importing bytes package directly in multiple places.
func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	var found int
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := subtle.ConstantTimeCompare(haystack[i:i+len(needle)], needle)
		found |= match
	}
	return found == 1
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
	if t > 1024 {
		return fmt.Errorf("Argon2 time too high (max %d)", 1024)
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

// checkMinEntropy performs a conservative entropy check.
// For small buffers (<64 bytes) it only checks for obvious constant data.
// For larger buffers it computes a Shannon-entropy heuristic.
func checkMinEntropy(data []byte) error {
	if len(data) == 0 {
		return errors.New("data too short for entropy check")
	}

	if len(data) < 64 {
		// Lightweight sanity: ensure data is not all the same byte
		first := data[0]
		allSame := true
		for _, b := range data {
			if b != first {
				allSame = false
				break
			}
		}
		if allSame {
			return errors.New("insufficient entropy: data appears constant")
		}
		// accept otherwise
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

	const minEntropy = 7.5
	if entropy < minEntropy {
		return fmt.Errorf("insufficient entropy: %.2f bits/byte (min %.2f)", entropy, minEntropy)
	}
	return nil
}

// validateRandomness ensures crypto/rand is working properly.
func validateRandomness() error {
	test := make([]byte, 64)
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

	// Reject percent-encoded traversal patterns
	if decoded, err := urlPathUnescape(out); err == nil {
		if decoded != out {
			// if unescaping reveals traversal or backslashes, reject
			if strings.Contains(decoded, "..") || strings.ContainsAny(decoded, `\`) {
				return "", errors.New("path contains suspicious encoded content")
			}
			out = decoded
		}
	} else {
		// malformed encoding
		return "", fmt.Errorf("malformed path encoding: %w", err)
	}

	// Normalize path separators
	normalized := filepath.FromSlash(out)

	// Get absolute path first to handle relative paths correctly
	abs, err := filepath.Abs(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Clean the path
	clean := filepath.Clean(abs)

	// If not allowed, refuse absolute paths outside cwd
	if !allowAbsolute {
		if filepath.IsAbs(clean) {
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
	}

	// Ensure parent exists and is not a symlink
	parent := filepath.Dir(clean)
	parentInfo, perr := os.Lstat(parent)
	if perr != nil {
		return "", fmt.Errorf("parent directory does not exist or cannot be lstat'd: %w", perr)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("parent directory is a symlink (refuse to write into symlinked dir)")
	}

	// Validate components for control chars and lengths
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return "", errors.New("path contains parent directory reference")
		}
		if p == "." || len(p) == 0 {
			continue
		}
		if len(p) > 255 {
			return "", errors.New("path component too long")
		}
		for _, rc := range p {
			if rc < 32 || rc == 127 {
				return "", errors.New("path contains control characters")
			}
		}
	}

	return clean, nil
}

// Helper to safely unescape URL-like percent encoding for paths.
func urlPathUnescape(s string) (string, error) {
	// Replace '+' with percent-encoding not desired for paths, use QueryUnescape is not appropriate.
	// Use a conservative approach: run path unescape.
	// Implement simple percent decoding for ASCII hex sequences.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", errors.New("invalid percent-encoding")
			}
			hi := fromHexChar(s[i+1])
			lo := fromHexChar(s[i+2])
			if hi < 0 || lo < 0 {
				return "", errors.New("invalid percent-encoding")
			}
			out = append(out, byte((hi<<4)|lo))
			i += 2
		} else {
			out = append(out, c)
		}
	}
	return string(out), nil
}

func fromHexChar(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// setSecurePermissions sets platform-appropriate secure permissions.
func setSecurePermissions(path string) error {
	if runtime.GOOS == "windows" {
		// On Windows, remove inherited ACEs from the DACL to ensure only explicit permissions.
  // On Windows, remove inherited ACEs from the DACL and set an explicit DACL for the current user only.
  var tok windows.Token
  if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
  	return fmt.Errorf("failed to open process token: %w", err)
  }
  defer tok.Close()

  tu, err := tok.GetTokenUser()
  if err != nil {
  	return fmt.Errorf("failed to get token user: %w", err)
  }
  if tu == nil || tu.User == nil || tu.User.Sid == nil {
  	return errors.New("failed to get current user SID")
  }
  sid := tu.User.Sid

  ea := windows.EXPLICIT_ACCESS{
  	AccessPermissions: windows.GENERIC_ALL,
  	AccessMode:        windows.SET_ACCESS,
  	Inheritance:       windows.NO_INHERITANCE,
  	Trustee: windows.TRUSTEE{
  		TrusteeForm:  windows.TRUSTEE_IS_SID,
  		TrusteeType:  windows.TRUSTEE_IS_USER,
  		TrusteeValue: windows.TrusteeValueFromSID(sid),
  	},
  }

  var dacl *windows.ACL
  if err := windows.SetEntriesInAcl(1, &ea, nil, &dacl); err != nil {
  	return fmt.Errorf("failed to build DACL: %w", err)
  }
  defer windows.LocalFree(windows.Handle(unsafe.Pointer(dacl)))

  if err := windows.SetNamedSecurityInfo(
  	path,
  	windows.SE_FILE_OBJECT,
  	windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
  	nil, nil,
  	dacl, nil,
  ); err != nil {
  	return fmt.Errorf("failed to apply secure DACL: %w", err)
  }
  if err := windows.SetNamedSecurityInfo(
  	path,
  	windows.SE_FILE_OBJECT,
  	windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
  	nil, nil,
  	dacl, nil,
  ); err != nil {
  	return fmt.Errorf("failed to apply secure DACL: %w", err)
  }
		}
		return nil
	}
	// On Unix-like systems, ensure 0600.
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != secureFilePerms {
		if err := os.Chmod(path, secureFilePerms); err != nil {
			return fmt.Errorf("failed to set secure permissions: %w", err)
		}
	}
	return nil
}

/*** Secure temp creation and atomic write ***/

// createSecureTempFile creates a temp file name and opens it atomically with O_CREATE|O_EXCL and secure mode.
func createSecureTempFile(dir string) (*os.File, string, error) {
	// random suffix
	r := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, r); err != nil {
		return nil, "", err
	}
	name := ".chachacrypt-" + hex.EncodeToString(r)
	path := filepath.Join(dir, name)
	// Use OpenFile with O_CREATE|O_EXCL to avoid races and set the desired mode directly.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(secureFilePerms))
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

// atomicWriteReplace writes to a secure temporary file and renames into place.
func atomicWriteReplace(tempDir, finalPath string, writer func(*os.File) error, force bool) error {
	dir := tempDir
	if dir == "" {
		dir = filepath.Dir(finalPath)
	}

	// Ensure parent dir identity before creation
	dirStatBefore, serr := os.Lstat(dir)
	if serr != nil {
		// fallback to system temp dir if target dir not available
		fmt.Fprintln(os.Stderr, "Warning: target directory not available; using system temp dir for safety")
		dir = os.TempDir()
		dirStatBefore, serr = os.Lstat(dir)
		if serr != nil {
			return fmt.Errorf("failed to stat temp dir: %w", serr)
		}
	}

	// Reject symlinked directories
	if dirStatBefore.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("target directory is a symlink: %s", dir)
	}
	if runtime.GOOS != "windows" && dirStatBefore.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("target directory is group/other writable: %s", dir)
	}

	// Create temp file securely
	var tmpFile *os.File
	var tmpPath string
	var err error
	const maxAttempts = 8
	created := false
	for i := 0; i < maxAttempts; i++ {
		tmpFile, tmpPath, err = createSecureTempFile(dir)
		if err == nil {
			created = true
			break
		}
	}
	if !created {
		return fmt.Errorf("create temp failed: %w", err)
	}

	// Verify directory identity didn't change
	dirStatAfter, dserr := os.Lstat(dir)
	if dserr != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("lstat temp dir after create failed: %w", dserr)
	}
	if !os.SameFile(dirStatBefore, dirStatAfter) {
		tmpFile.Close()
		os.Remove(tmpPath)
		return errors.New("directory changed during temp file creation (possible race)")
	}

	// Ensure secure permissions on temp
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

	// Let writer do work
	if writeErr = writer(tmpFile); writeErr != nil {
		return fmt.Errorf("write temp: %w", writeErr)
	}

	if writeErr = tmpFile.Sync(); writeErr != nil {
		return fmt.Errorf("sync temp: %w", writeErr)
	}
	if writeErr = tmpFile.Close(); writeErr != nil {
		return fmt.Errorf("close temp: %w", writeErr)
	}

	// Sync parent directory on Unix systems to ensure rename is durable.
	if runtime.GOOS != "windows" {
		if dfd, err := os.Open(filepath.Dir(finalPath), os.O_RDONLY, 0); err == nil {
			// Best-effort sync, ignore error as not all filesystems support it.
			_ = dfd.Sync()
			_ = dfd.Close()
		}
	}

	// If destination exists, handle
	if _, statErr := os.Stat(finalPath); statErr == nil {
		if !force {
			return fmt.Errorf("destination exists: %s (use --force)", finalPath)
		}
		if remErr := os.Remove(finalPath); remErr != nil {
			return fmt.Errorf("remove existing dest: %w", remErr)
		}
	}

	// Try atomic rename
	if err = os.Rename(tmpPath, finalPath); err == nil {
		return setSecurePermissions(finalPath)
	}

	// If rename failed due to cross-device, fallback to verified copy
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		fmt.Fprintf(os.Stderr, "Warning: cross-device move, using verified copy for %s\n", finalPath)
		src, rerr := os.Open(tmpPath)
		if rerr != nil {
			return fmt.Errorf("open temp for copy: %w", rerr)
		}
		defer src.Close()

		dst, werr := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(secureFilePerms))
		if werr != nil {
			return fmt.Errorf("create dest for copy: %w", werr)
		}

		hsrc := sha256.New()
		mw := io.MultiWriter(dst, hsrc)
		if _, cerr := io.Copy(mw, src); cerr != nil {
			dst.Close()
			return fmt.Errorf("copy temp to dest: %w", cerr)
		}
		if serr := dst.Sync(); serr != nil {
			dst.Close()
			return fmt.Errorf("sync dest: %w", serr)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close dest after copy: %w", err)
		}

		// Verify sizes match
		srcInfo, err := os.Stat(tmpPath)
		if err != nil {
			return fmt.Errorf("verification failed: could not stat temp file: %w", err)
		}
		dstInfo, err := os.Stat(finalPath)
		if err != nil {
			return fmt.Errorf("verification failed: could not stat dest file: %w", err)
		}
		if srcInfo.Size() != dstInfo.Size() {
			return fmt.Errorf("verification failed: size mismatch after copy")
		}

		// Verify checksum
		dstR, err := os.Open(finalPath)
		if err != nil {
			return fmt.Errorf("verification failed: could not open dest for checksum: %w", err)
		}
		defer dstR.Close()
		hdst := sha256.New()
		if _, rerr := io.Copy(hdst, dstR); rerr != nil {
			return fmt.Errorf("verification failed: could not checksum dest: %w", rerr)
		}
		if !bytesEqual(hsrc.Sum(nil), hdst.Sum(nil)) {
			return errors.New("verification failed: checksum mismatch after copy")
		}

		// Remove temp after success
		if rerr := os.Remove(tmpPath); rerr != nil {
			return fmt.Errorf("remove temp after copy: %w", rerr)
		}
		return nil
	}

	return fmt.Errorf("rename temp: %w", err)
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
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

	// No strict entropy check for nonces; rely on crypto/rand and validateRandomness on startup.

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

	// No strict entropy check for nonces.

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

/*** Securely open input files to prevent symlink TOCTOU bypass ***/

func secureOpenReadOnly(path string) (*os.File, error) {
	// Prevent symlink traversal and TOCTOU by using OS-specific calls.
	if runtime.GOOS == "windows" {
		// On Windows, use CreateFile with FILE_FLAG_OPEN_REPARSE_POINT to open without following symlinks/junctions.
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, fmt.Errorf("windows path conversion: %w", err)
		}
		// OPEN_EXISTING: Only open if it exists; READ access; share mode READ.
		handle, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, fmt.Errorf("open input (CreateFile): %w", err)
		}
		// Check if opened file is actually a reparse point (symlink/junction).
		var fi windows.FileAttributeTagInfo
		err = windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&fi)), uint32(unsafe.Sizeof(fi)))
  if err != nil {
  	windows.CloseHandle(handle)
  	return nil, fmt.Errorf("could not get file information to check for reparse point: %w", err)
  }
  if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || fi.ReparseTag != 0 {
  	windows.CloseHandle(handle)
  	return nil, errors.New("refuse to open input: path is a reparse point (symlink or junction)")
  }
  // Wrap Windows handle in *os.File (will take ownership).
  return os.NewFile(uintptr(handle), path), nil
	}

	// Non-Windows: use Lstat to detect symlinks then open with O_NOFOLLOW.
	linfo, lerr := os.Lstat(path)
	if lerr != nil {
		return nil, fmt.Errorf("open input lstat: %w", lerr)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refuse to open input: path is a symlink")
	}

	// On Unix-like, attempt to use O_NOFOLLOW for atomic open.
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC
	flags |= syscall.O_NOFOLLOW
	fd, err := syscall.Open(path, flags, 0)
	if err == nil {
		return os.NewFile(uintptr(fd), path), nil
	}
	// Fallback to os.Open (we already checked symlink).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	return f, nil
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
	in, err := secureOpenReadOnly(inPath)
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
	in, err := secureOpenReadOnly(inPath)
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
	in, err := secureOpenReadOnly(inPath)
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
