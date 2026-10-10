// chachacrypt
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
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

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

	// Platform-specific secure permissions.
	secureFilePerms = 0o600 // Owner read/write only on Unix and Windows
	secureDirPerms  = 0o700 // Owner rwx only on Unix

	// Linter/Magic Number constants.
	maxASCIIValue       = 127
	maxConsecutiveChars = 4
	minComplexityGroups = 3
	maxArgonTimeLimit   = 1024
	maxThreadLimit      = 64
	maxPathLength       = 4096
	maxPathComponentLen = 255
	hexShift            = 4
	hexBase             = 10
	randomSuffixLen     = 8
	targetOS            = "windows"
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

func secureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)

	for i := range b {
		b[i] = 0xFF
	}
	runtime.KeepAlive(b)

	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func clearBuf(b []byte) {
	if len(b) == 0 {
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
	var errMsg string
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		errMsg = "Error: file access issue — check paths/permissions."
	} else if errors.Is(err, context.Canceled) {
		errMsg = "Error: operation cancelled."
	} else {
		errMsg = fmt.Sprintf("Error: %v", err)
	}
	fmt.Fprintln(os.Stderr, errMsg)
	os.Exit(1)
}

func readPasswordPrompt(prompt string) ([]byte, error) {
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

func checkComplexity(pw []byte) (hasUpper, hasLower, hasDigit, hasSpecial bool, err error) {
	consecutiveCount := 0
	var lastRune rune

	for i := 0; i < len(pw); {
		r, size := utf8.DecodeRune(pw[i:])
		if r == utf8.RuneError && size == 1 {
			r = rune(pw[i])
			size = 1
		}
		if r == 0 {
			return false, false, false, false, errors.New("password contains null byte")
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
			if r > maxASCIIValue {
				hasSpecial = true
			}
		}
		if r == lastRune {
			consecutiveCount++
			if consecutiveCount >= maxConsecutiveChars {
				return false, false, false, false, errors.New(
					"password contains too many consecutive identical characters",
				)
			}
		} else {
			consecutiveCount = 1
			lastRune = r
		}
		i += size
	}
	return hasUpper, hasLower, hasDigit, hasSpecial, nil
}

func validatePasswordStrength(pw []byte) error {
	if len(pw) < minPasswordLength {
		return fmt.Errorf("password too short (minimum %d characters)", minPasswordLength)
	}
	if len(pw) > maxPasswordLength {
		return fmt.Errorf("password too long (maximum %d characters)", maxPasswordLength)
	}

	hasUpper, hasLower, hasDigit, hasSpecial, err := checkComplexity(pw)
	if err != nil {
		return err
	}

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

	if charTypeCount < minComplexityGroups {
		return errors.New(
			"password must contain at least three types: uppercase, lowercase, digits, or special characters",
		)
	}

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
		if bytesContains(lowerPw, pat) {
			return errors.New("password contains a common weak pattern")
		}
	}

	return nil
}

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

func serializeHeaderForMAC(hdr *fileHeader) ([]byte, error) {
	tmp := *hdr
	clearBuf(tmp.HeaderMAC[:])
	return serializeHeaderCanonical(&tmp)
}

func buildAAD(hdr *fileHeader, chunkIndex uint64) ([]byte, error) {
	hb, err := serializeHeaderCanonical(hdr)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_, err = b.Write(hb)
	if err != nil {
		return nil, err
	}
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
	_, err = m.Write(b)
	if err != nil {
		return nil, err
	}
	return m.Sum(nil), nil
}

/*** Argon2 param validation ***/

func validateArgon2Params(t, mem uint32, threads uint8) error {
	if t < minArgonTime {
		return fmt.Errorf("Argon2 time too low (min %d)", minArgonTime)
	}
	if t > maxArgonTimeLimit {
		return fmt.Errorf("Argon2 time too high (max %d)", maxArgonTimeLimit)
	}
	if mem < minArgonMemory {
		return fmt.Errorf("Argon2 memory too low (min %d KiB)", minArgonMemory)
	}
	if mem > maxArgonMemory {
		return fmt.Errorf("Argon2 memory too high (max %d KiB)", maxArgonMemory)
	}
	maxThreads := uint8(runtime.NumCPU())
	if maxThreads > maxThreadLimit {
		maxThreads = maxThreadLimit
	}
	if threads < minArgonThreads || threads > maxThreads {
		return fmt.Errorf("Argon2 threads out of bounds (min %d max %d)", minArgonThreads, maxThreads)
	}
	return nil
}

/*** Path safety and atomic write ***/

func validatePathComponents(clean string) error {
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." {
			return errors.New("path contains parent directory reference")
		}
		if p == "." || len(p) == 0 {
			continue
		}
		if len(p) > maxPathComponentLen {
			return errors.New("path component too long")
		}
		for _, rc := range p {
			if rc < 32 || rc == 127 {
				return errors.New("path contains control characters")
			}
		}
	}
	return nil
}

func safeOutputPath(out string, allowAbsolute bool) (string, error) {
	if out == "" {
		return "", errors.New("empty output path")
	}
	if len(out) > maxPathLength {
		return "", errors.New("path too long")
	}
	if strings.IndexByte(out, 0) != -1 {
		return "", errors.New("null byte in path")
	}

	decoded, err := urlPathUnescape(out)
	if err != nil {
		return "", fmt.Errorf("malformed path encoding: %w", err)
	}
	if decoded != out {
		if strings.Contains(decoded, "..") || strings.ContainsAny(decoded, `\`) {
			return "", errors.New("path contains suspicious encoded content")
		}
		out = decoded
	}

	normalized := filepath.FromSlash(out)

	abs, err := filepath.Abs(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	clean := filepath.Clean(abs)

	if !allowAbsolute {
		if filepath.IsAbs(clean) {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return "", fmt.Errorf("failed to get working directory: %w", cwdErr)
			}
			rel, relErr := filepath.Rel(cwd, clean)
			if relErr != nil {
				return "", fmt.Errorf("failed to compute relative path: %w", relErr)
			}
			if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
				return "", errors.New("output path is outside working directory")
			}
		}
	}

	parent := filepath.Dir(clean)
	parentInfo, perr := os.Lstat(parent)
	if perr != nil {
		return "", fmt.Errorf("parent directory does not exist or cannot be lstat'd: %w", perr)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("parent directory is a symlink (refuse to write into symlinked dir)")
	}

	if compErr := validatePathComponents(clean); compErr != nil {
		return "", compErr
	}

	return clean, nil
}

func urlPathUnescape(s string) (string, error) {
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
			out = append(out, byte((hi<<hexShift)|lo))
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
		return int(c - 'a' + hexBase)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + hexBase)
	default:
		return -1
	}
}

func setSecurePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != secureFilePerms {
		if chmodErr := os.Chmod(path, secureFilePerms); chmodErr != nil {
			return fmt.Errorf("failed to set secure permissions: %w", chmodErr)
		}
	}
	return nil
}

/*** Secure temp creation and atomic write ***/

func closeQuietly(c io.Closer) {
	_ = c.Close()
}

func removeQuietly(name string) {
	_ = os.Remove(name)
}

func createSecureTempFile(dir string) (*os.File, string, error) {
	r := make([]byte, randomSuffixLen)
	if _, err := io.ReadFull(rand.Reader, r); err != nil {
		return nil, "", err
	}
	name := ".chachacrypt-" + hex.EncodeToString(r)
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(secureFilePerms))
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

func copyWithVerification(src, dst string) error {
	rSrc, rErr := os.Open(src)
	if rErr != nil {
		return fmt.Errorf("open temp for copy: %w", rErr)
	}
	defer closeQuietly(rSrc)

	wDst, wErr := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(secureFilePerms))
	if wErr != nil {
		return fmt.Errorf("create dest for copy: %w", wErr)
	}
	defer closeQuietly(wDst)

	hsrc := sha256.New()
	mw := io.MultiWriter(wDst, hsrc)
	if _, cerr := io.Copy(mw, rSrc); cerr != nil {
		return fmt.Errorf("copy temp to dest: %w", cerr)
	}
	if serr := wDst.Sync(); serr != nil {
		return fmt.Errorf("sync dest: %w", serr)
	}
	srcInfo, statErr := os.Stat(src)
	if statErr != nil {
		return fmt.Errorf("verification failed: could not stat temp file: %w", statErr)
	}
	dstInfo, statErr2 := os.Stat(dst)
	if statErr2 != nil {
		return fmt.Errorf("verification failed: could not stat dest file: %w", statErr2)
	}
	if srcInfo.Size() != dstInfo.Size() {
		return errors.New("verification failed: size mismatch after copy")
	}

	dstR, openErr := os.Open(dst)
	if openErr != nil {
		return fmt.Errorf("verification failed: could not open dest for checksum: %w", openErr)
	}
	defer closeQuietly(dstR)
	hdst := sha256.New()
	if _, copyErr := io.Copy(hdst, dstR); copyErr != nil {
		return fmt.Errorf("verification failed: could not checksum dest: %w", copyErr)
	}
	if !bytesEqual(hsrc.Sum(nil), hdst.Sum(nil)) {
		return errors.New("verification failed: checksum mismatch after copy")
	}

	if rmErr := os.Remove(src); rmErr != nil {
		return fmt.Errorf("remove temp after copy: %w", rmErr)
	}
	return nil
}

func atomicWriteReplace(tempDir, finalPath string, writer func(*os.File) error, force bool) error {
	dir := tempDir
	if dir == "" {
		dir = filepath.Dir(finalPath)
	}

	dirStatBefore, serr := os.Lstat(dir)
	if serr != nil {
		fmt.Fprintln(os.Stderr, "Warning: target directory not available; using system temp dir for safety")
		dir = os.TempDir()
		dirStatBefore, serr = os.Lstat(dir)
		if serr != nil {
			return fmt.Errorf("failed to stat temp dir: %w", serr)
		}
	}

	if dirStatBefore.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("target directory is a symlink: %s", dir)
	}
	if runtime.GOOS != targetOS && dirStatBefore.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("target directory is group/other writable: %s", dir)
	}

	var tmpFile *os.File
	var tmpPath string
	var err error
	const maxAttempts = 8
	created := false
	for range maxAttempts {
		tmpFile, tmpPath, err = createSecureTempFile(dir)
		if err == nil {
			created = true
			break
		}
	}
	if !created {
		return fmt.Errorf("create temp failed: %w", err)
	}

	dirStatAfter, dserr := os.Lstat(dir)
	if dserr != nil {
		closeQuietly(tmpFile)
		removeQuietly(tmpPath)
		return fmt.Errorf("lstat temp dir after create failed: %w", dserr)
	}
	if !os.SameFile(dirStatBefore, dirStatAfter) {
		closeQuietly(tmpFile)
		removeQuietly(tmpPath)
		return errors.New("directory changed during temp file creation (possible race)")
	}

	if permErr := setSecurePermissions(tmpPath); permErr != nil {
		closeQuietly(tmpFile)
		removeQuietly(tmpPath)
		return permErr
	}

	var writeErr error
	defer func() {
		closeQuietly(tmpFile)
		if writeErr != nil || !force {
			removeQuietly(tmpPath)
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

	if runtime.GOOS != targetOS {
		dfd, openErr := os.Open(filepath.Dir(finalPath))
		if openErr == nil {
			if fi, fiErr := dfd.Stat(); fiErr != nil || !fi.IsDir() {
				closeQuietly(dfd)
				return fmt.Errorf("invalid parent directory: %w", fiErr)
			}
			_ = dfd.Sync()
			closeQuietly(dfd)
		}
	}

	if _, statErr := os.Stat(finalPath); statErr == nil {
		if !force {
			return fmt.Errorf("destination exists: %s (use --force)", finalPath)
		}
		if remErr := os.Remove(finalPath); remErr != nil {
			return fmt.Errorf("remove existing dest: %w", remErr)
		}
	}

	if err = os.Rename(tmpPath, finalPath); err == nil {
		return setSecurePermissions(finalPath)
	}

	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		fmt.Fprintf(os.Stderr, "Warning: cross-device move, using verified copy for %s\n", finalPath)
		return copyWithVerification(tmpPath, finalPath)
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
	in io.Reader,
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

	aadNew, err := buildAAD(newHdr, idx)
	if err != nil {
		return true, err
	}

	newCT := newAEAD.Seal(nil, newNonce, pt, aadNew)
	if err = writeChunkFrame(out, newNonce, newCT); err != nil {
		zero(newCT)
		return true, err
	}
	zero(newCT)

	if verbose {
		fmt.Fprintf(os.Stderr, "Rotated chunk %d\n", idx)
	}
	return false, nil
}

func rotateChunks(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	origHdr *fileHeader,
	oldAEAD cipherAEAD,
	newHdr *fileHeader,
	newAEAD cipherAEAD,
	verbose bool,
) error {
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

/*** File operations ***/

func readHeader(r io.Reader) (*fileHeader, []byte, error) {
	buf := make([]byte, headerTotalSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, fmt.Errorf("read header failed: %w", err)
	}

	hdr := &fileHeader{}
	rdr := bytes.NewReader(buf)

	if _, err := io.ReadFull(rdr, hdr.Magic[:]); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hdr.Magic[:], []byte(MagicString)) {
		return nil, nil, errors.New("invalid file magic: not a chachacrypt file")
	}

	if err := binary.Read(rdr, binary.BigEndian, &hdr.Version); err != nil {
		return nil, nil, err
	}
	if hdr.Version != fileVersion {
		return nil, nil, fmt.Errorf("unsupported file version: %d", hdr.Version)
	}

	if err := binary.Read(rdr, binary.BigEndian, &hdr.KeyVersion); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(rdr, binary.BigEndian, &hdr.Timestamp); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(rdr, binary.BigEndian, &hdr.ArgonTime); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(rdr, binary.BigEndian, &hdr.ArgonMemory); err != nil {
		return nil, nil, err
	}
	if b, err2 := rdr.ReadByte(); err2 != nil {
		return nil, nil, err2
	} else {
		hdr.ArgonThreads = b
	}
	if _, err := io.ReadFull(rdr, hdr.Salt[:]); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(rdr, binary.BigEndian, &hdr.ChunkSize); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(rdr, binary.BigEndian, &hdr.NonceSize); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rdr, hdr.Reserved[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rdr, hdr.HeaderMAC[:]); err != nil {
		return nil, nil, err
	}

	return hdr, buf, nil
}

func writeHeader(w io.Writer, hdr *fileHeader, macKey []byte) error {
	mac, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		return err
	}
	copy(hdr.HeaderMAC[:], mac)
	hb, err := serializeHeaderCanonical(hdr)
	if err != nil {
		return err
	}
	if _, err := w.Write(hb); err != nil {
		return err
	}
	return nil
}

func encryptFile(ctx context.Context, inPath, outPath string, password []byte, argonTime, argonMemory uint32, argonThreads uint8, chunkSize uint32, force, verbose, allowAbsolute bool) error {
	// Validate output path.
	cleanOut, err := safeOutputPath(outPath, allowAbsolute)
	if err != nil {
		return err
	}

	// Reject symlink inputs.
	if info, lerr := os.Lstat(inPath); lerr != nil {
		return fmt.Errorf("input file lstat failed: %w", lerr)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("input file is a symlink, refusing to follow")
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer closeQuietly(in)

	// Reject group/other writable inputs on non‑Windows.
	if runtime.GOOS != targetOS {
		if info, serr := in.Stat(); serr == nil {
			if info.Mode().Perm()&0o022 != 0 {
				return errors.New("input file is group or world writable")
			}
		}
	}

	if chunkSize == 0 {
		chunkSize = defaultChunkSize
	}
	if chunkSize < minChunkSize || chunkSize > maxChunkSize {
		return fmt.Errorf("chunk size out of bounds (%d - %d bytes)", minChunkSize, maxChunkSize)
	}

	if err := validateArgon2Params(argonTime, argonMemory, argonThreads); err != nil {
		return err
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("salt generation failed: %w", err)
	}
	defer zero(salt)

	masterKey := deriveMasterKeyArgon(password, salt, argonTime, argonMemory, argonThreads)
	defer secureZero(masterKey)

	encKey, macKey, err := deriveEncAndMacKeys(masterKey)
	if err != nil {
		return err
	}
	defer secureZero(encKey)
	defer secureZero(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	var magic [magicLen]byte
	copy(magic[:], MagicString)

	var saltArr [saltSize]byte
	copy(saltArr[:], salt)

	hdr := &fileHeader{
		Magic:        magic,
		Version:      fileVersion,
		KeyVersion:   1,
		Timestamp:    time.Now().Unix(),
		ArgonTime:    argonTime,
		ArgonMemory:  argonMemory,
		ArgonThreads: argonThreads,
		Salt:         saltArr,
		ChunkSize:    chunkSize,
		NonceSize:    nonceSize,
	}

	mac, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		return err
	}
	copy(hdr.HeaderMAC[:], mac)

	return atomicWriteReplace("", cleanOut, func(tmp *os.File) error {
		if err := writeHeader(tmp, hdr, macKey); err != nil {
			return err
		}
		return encryptChunks(ctx, in, tmp, hdr, aead, verbose)
	}, force)
}

func decryptFile(ctx context.Context, inPath, outPath string, password []byte, force, verbose, allowAbsolute bool) error {
	cleanOut, err := safeOutputPath(outPath, allowAbsolute)
	if err != nil {
		return err
	}

	if info, lerr := os.Lstat(inPath); lerr != nil {
		return fmt.Errorf("input file lstat failed: %w", lerr)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("input file is a symlink, refusing to follow")
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer closeQuietly(in)

	hdr, _, err := readHeader(in)
	if err != nil {
		return err
	}

	if hdr.NonceSize != nonceSize {
		return fmt.Errorf("unsupported nonce size: %d", hdr.NonceSize)
	}

	if err := validateArgon2Params(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return fmt.Errorf("invalid parameters in file header: %w", err)
	}

	masterKey := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer secureZero(masterKey)

	encKey, macKey, err := deriveEncAndMacKeys(masterKey)
	if err != nil {
		return err
	}
	defer secureZero(encKey)
	defer secureZero(macKey)

	expectedMAC, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		return err
	}
	if !secureCompare(expectedMAC, hdr.HeaderMAC[:]) {
		return errors.New("header authentication failed: wrong password or tampered header")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	return atomicWriteReplace("", cleanOut, func(tmp *os.File) error {
		return decryptChunks(ctx, in, tmp, hdr, aead, verbose)
	}, force)
}

func rotateFile(ctx context.Context, inPath, outPath string, oldPassword, newPassword []byte, newArgonTime, newArgonMemory uint32, newArgonThreads uint8, force, verbose, allowAbsolute bool) error {
	cleanOut, err := safeOutputPath(outPath, allowAbsolute)
	if err != nil {
		return err
	}

	if info, lerr := os.Lstat(inPath); lerr != nil {
		return fmt.Errorf("input file lstat failed: %w", lerr)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("input file is a symlink, refusing to follow")
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer closeQuietly(in)

	hdr, _, err := readHeader(in)
	if err != nil {
		return err
	}

	if hdr.NonceSize != nonceSize {
		return fmt.Errorf("unsupported nonce size: %d", hdr.NonceSize)
	}

	if err := validateArgon2Params(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return fmt.Errorf("invalid parameters in file header: %w", err)
	}

	oldMasterKey := deriveMasterKeyArgon(oldPassword, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer secureZero(oldMasterKey)

	oldEncKey, oldMacKey, err := deriveEncAndMacKeys(oldMasterKey)
	if err != nil {
		return err
	}
	defer secureZero(oldEncKey)
	defer secureZero(oldMacKey)

	expectedMAC, err := computeHeaderHMAC(hdr, oldMacKey)
	if err != nil {
		return err
	}
	if !secureCompare(expectedMAC, hdr.HeaderMAC[:]) {
		return errors.New("authentication failed: wrong old password or tampered header")
	}

	oldAEAD, err := chacha20poly1305.NewX(oldEncKey)
	if err != nil {
		return fmt.Errorf("failed to create old AEAD: %w", err)
	}

	if newArgonTime == 0 {
		newArgonTime = hdr.ArgonTime
	}
	if newArgonMemory == 0 {
		newArgonMemory = hdr.ArgonMemory
	}
	if newArgonThreads == 0 {
		newArgonThreads = hdr.ArgonThreads
	}
	if err := validateArgon2Params(newArgonTime, newArgonMemory, newArgonThreads); err != nil {
		return err
	}

	newSalt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return err
	}
	defer zero(newSalt)

	newMasterKey := deriveMasterKeyArgon(newPassword, newSalt, newArgonTime, newArgonMemory, newArgonThreads)
	defer secureZero(newMasterKey)

	newEncKey, newMacKey, err := deriveEncAndMacKeys(newMasterKey)
	if err != nil {
		return err
	}
	defer secureZero(newEncKey)
	defer secureZero(newMacKey)

	newAEAD, err := chacha20poly1305.NewX(newEncKey)
	if err != nil {
		return fmt.Errorf("failed to create new AEAD: %w", err)
	}

	newHdr := *hdr
	newHdr.Timestamp = time.Now().Unix()
	newHdr.ArgonTime = newArgonTime
	newHdr.ArgonMemory = newArgonMemory
	newHdr.ArgonThreads = newArgonThreads
	copy(newHdr.Salt[:], newSalt)
	newHdr.KeyVersion = hdr.KeyVersion + 1

	return atomicWriteReplace("", cleanOut, func(tmp *os.File) error {
		if err := writeHeader(tmp, &newHdr, newMacKey); err != nil {
			return err
		}
		return rotateChunks(ctx, in, tmp, hdr, oldAEAD, &newHdr, newAEAD, verbose)
	}, force)
}

/*** CLI Main ***/

func main() {
	if err := run(); err != nil {
		die(err)
	}
	fmt.Println("Goodbye")
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	rotateCmd := flag.NewFlagSet("rotate", flag.ExitOnError)

	var (
		force       = encryptCmd.Bool("f", false, "Overwrite output file if it exists")
		verbose     = encryptCmd.Bool("v", false, "Enable verbose output")
		allowAbs    = encryptCmd.Bool("allow-abs", false, "Allow absolute output paths")
		argonT      = encryptCmd.Uint("argon-time", defaultArgonTime, "Argon2 time cost iterations")
		argonM      = encryptCmd.Uint("argon-memory", defaultArgonMemory/1024, "Argon2 memory cost in MiB")
		argonTh     = encryptCmd.Uint("argon-threads", defaultArgonThreads, "Argon2 parallelism threads")
		chunkSz     = encryptCmd.Uint("chunk-size", defaultChunkSize, "Chunk size in bytes")

		dForce    = decryptCmd.Bool("f", false, "Overwrite output file if it exists")
		dVerbose  = decryptCmd.Bool("v", false, "Enable verbose output")
		dAllowAbs = decryptCmd.Bool("allow-abs", false, "Allow absolute output paths")

		rForce    = rotateCmd.Bool("f", false, "Overwrite output file if it exists")
		rVerbose  = rotateCmd.Bool("v", false, "Enable verbose output")
		rAllowAbs = rotateCmd.Bool("allow-abs", false, "Allow absolute output paths")
		rArgonT   = rotateCmd.Uint("argon-time", 0, "New Argon2 time cost")
		rArgonM   = rotateCmd.Uint("argon-memory", 0, "New Argon2 memory cost in MiB")
		rArgonTh  = rotateCmd.Uint("argon-threads", 0, "New Argon2 parallelism threads")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(usageExit)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "encrypt":
		_ = encryptCmd.Parse(os.Args[2:])
		args := encryptCmd.Args()
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Error: exactly two positional arguments (input and output) required")
			encryptCmd.Usage()
			os.Exit(usageExit)
		}
		inPath, outPath := args[0], args[1]

		password, err := readPasswordPrompt("Enter encryption password: ")
		if err != nil {
			return err
		}
		defer secureZero(password)

		confirm, err := readPasswordPrompt("Confirm encryption password: ")
		if err != nil {
			secureZero(password)
			return err
		}
		defer secureZero(confirm)

		if !secureCompare(password, confirm) {
			return errors.New("passwords do not match")
		}

		if err := validatePasswordStrength(password); err != nil {
			return fmt.Errorf("password too weak: %w", err)
		}

		// Validate numeric flags.
		if *argonT < minArgonTime || *argonT > maxArgonTimeLimit {
			return fmt.Errorf("argon-time must be between %d and %d", minArgonTime, maxArgonTimeLimit)
		}
		if *argonM < minArgonMemory/1024 || *argonM > maxArgonMemory/1024 {
			return fmt.Errorf("argon-memory must be between %d and %d MiB", minArgonMemory/1024, maxArgonMemory/1024)
		}
		if *argonM > (1<<32-1)/1024 {
			return errors.New("argon-memory value overflows uint32 when converted to KiB")
		}
		if *argonTh < minArgonThreads || *argonTh > maxThreadLimit {
			return fmt.Errorf("argon-threads must be between %d and %d", minArgonThreads, maxThreadLimit)
		}
		if *chunkSz < minChunkSize || *chunkSz > maxChunkSize {
			return fmt.Errorf("chunk-size must be between %d and %d", minChunkSize, maxChunkSize)
		}

		memoryKiB := uint32(*argonM) * 1024
		err = encryptFile(ctx, inPath, outPath, password, uint32(*argonT), memoryKiB, uint8(*argonTh), uint32(*chunkSz), *force, *verbose, *allowAbs)
		if err != nil {
			return err
		}
		if *verbose {
			fmt.Println("Encryption completed successfully.")
		}

	case "decrypt":
		_ = decryptCmd.Parse(os.Args[2:])
		args := decryptCmd.Args()
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Error: exactly two positional arguments (input and output) required")
			decryptCmd.Usage()
			os.Exit(usageExit)
		}
		inPath, outPath := args[0], args[1]

		password, err := readPasswordPrompt("Enter decryption password: ")
		if err != nil {
			return err
		}
		defer secureZero(password)

		err = decryptFile(ctx, inPath, outPath, password, *dForce, *dVerbose, *dAllowAbs)
		if err != nil {
			return err
		}
		if *dVerbose {
			fmt.Println("Decryption completed successfully.")
		}

	case "rotate":
		_ = rotateCmd.Parse(os.Args[2:])
		args := rotateCmd.Args()
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Error: exactly two positional arguments (input and output) required")
			rotateCmd.Usage()
			os.Exit(usageExit)
		}
		inPath, outPath := args[0], args[1]

		oldPass, err := readPasswordPrompt("Enter current password: ")
		if err != nil {
			return err
		}
		defer secureZero(oldPass)

		newPass, err := readPasswordPrompt("Enter new password: ")
		if err != nil {
			secureZero(oldPass)
			return err
		}
		defer secureZero(newPass)

		confirm, err := readPasswordPrompt("Confirm new password: ")
		if err != nil {
			secureZero(oldPass)
			secureZero(newPass)
			return err
		}
		defer secureZero(confirm)

		if !secureCompare(newPass, confirm) {
			return errors.New("passwords do not match")
		}

		if err := validatePasswordStrength(newPass); err != nil {
			return fmt.Errorf("new password too weak: %w", err)
		}

		if *rArgonT > maxArgonTimeLimit {
			return fmt.Errorf("argon-time must not exceed %d", maxArgonTimeLimit)
		}
		if *rArgonM > maxArgonMemory/1024 {
			return fmt.Errorf("argon-memory must not exceed %d MiB", maxArgonMemory/1024)
		}
		if *rArgonM > 0 && *rArgonM > (1<<32-1)/1024 {
			return errors.New("argon-memory value overflows uint32 when converted to KiB")
		}
		if *rArgonTh > maxThreadLimit {
			return fmt.Errorf("argon-threads must not exceed %d", maxThreadLimit)
		}

		var newMemKiB uint32
		if *rArgonM > 0 {
			newMemKiB = uint32(*rArgonM) * 1024
		}

		err = rotateFile(ctx, inPath, outPath, oldPass, newPass, uint32(*rArgonT), newMemKiB, uint8(*rArgonTh), *rForce, *rVerbose, *rAllowAbs)
		if err != nil {
			return err
		}
		if *rVerbose {
			fmt.Println("Key/password rotation completed successfully.")
		}

	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcmd)
		printUsage()
		os.Exit(usageExit)
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  chachacrypt encrypt [options] <input> <output>")
	fmt.Println("  chachacrypt decrypt [options] <input> <output>")
	fmt.Println("  chachacrypt rotate  [options] <input> <output>")
	fmt.Println("Use subcommands with -h for detailed options.")
}
