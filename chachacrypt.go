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

	defaultChunkSize = 1 << 20
	maxChunkSize     = 16 << 20

	nonceSize = chacha20poly1305.NonceSizeX // 24

	derivedKeyBytes = 64
	keySize         = 32

	reservedLen = 7

	maxNonceLen = 1024
	maxCTSize   = 1 << 30

	usageExit = 2
)

const headerTotalSize = magicLen + 2 + 4 + 8 + 4 + 4 + 1 + saltSize + 4 + 2 + reservedLen + headerMACSize

const (
	// presets in KiB units for Argon2
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
	Magic        [magicLen]byte
	Version      uint16
	KeyVersion   uint32
	Timestamp    int64
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	Salt         [saltSize]byte
	ChunkSize    uint32
	NonceSize    uint16
	Reserved     [reservedLen]byte
	HeaderMAC    [headerMACSize]byte
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

/*** Utilities ***/

func die(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

func zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
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

/*** Header serialization / AAD ***/

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
	for i := 0; i < headerMACSize; i++ {
		tmp.HeaderMAC[i] = 0
	}
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

/*** KDF and key derivation ***/

func deriveMasterKeyArgon(password, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, t, mem, threads, derivedKeyBytes)
}

func deriveEncAndMacKeys(master []byte) ([]byte, []byte, error) {
	r := hkdf.New(sha256.New, master, nil, []byte("chachacrypt-enc-mac-v1"))
	encKey := make([]byte, keySize)
	macKey := make([]byte, keySize)
	if _, err := io.ReadFull(r, encKey); err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, macKey); err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, err
	}
	return encKey, macKey, nil
}

func computeHeaderHMAC(hdr *fileHeader, macKey []byte) ([]byte, error) {
	data, err := serializeHeaderForMAC(hdr)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, macKey)
	if _, err = h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

/*** Path safety & atomic write ***/

func safeOutputPath(out string, allowAbsolute bool) (string, error) {
	if out == "" {
		return "", errors.New("empty output path")
	}
	clean := filepath.Clean(out)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get cwd: %w", err)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return "", fmt.Errorf("evaluate path: %w", err)
	}
	if strings.HasPrefix(rel, "..") && !allowAbsolute {
		return "", errors.New("output path outside cwd; use --allow-absolute to override")
	}
	return abs, nil
}

func atomicWriteReplace(tempDir, finalPath string, writer func(*os.File) error, force bool) error {
	var err error
	dir := tempDir
	if dir == "" {
		dir = filepath.Dir(finalPath)
	}
	tmpFile, err := os.CreateTemp(dir, "chachacrypt-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err = writer(tmpFile); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	var dfd *os.File
	dfd, err = os.Open(filepath.Dir(finalPath))
	if err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}

	if _, err = os.Stat(finalPath); err == nil {
		if force {
			if err = os.Remove(finalPath); err != nil {
				return fmt.Errorf("remove existing dest: %w", err)
			}
		} else {
			return fmt.Errorf("destination exists: %s (use --force)", finalPath)
		}
	}

	if err = os.Rename(tmpPath, finalPath); err != nil {
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

/*** Chunk processors (small, no-named returns) ***/

func processOneEncrypt(ctx context.Context, in io.Reader, out io.Writer, hdr *fileHeader, aead cipherAEAD, buf []byte, idx uint64, verbose bool) (bool, error) {
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}
	n, rerr := io.ReadFull(in, buf)
	if rerr == io.EOF || (rerr == io.ErrUnexpectedEOF && n == 0) {
		return true, nil
	}
	if rerr != nil && rerr != io.ErrUnexpectedEOF {
		return true, fmt.Errorf("read input: %w", rerr)
	}
	if n == 0 {
		return true, nil
	}
	nonce := make([]byte, hdr.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return true, fmt.Errorf("nonce gen: %w", err)
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

func encryptChunks(ctx context.Context, in io.Reader, out io.Writer, hdr *fileHeader, aead cipherAEAD, verbose bool) error {
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

func processOneDecrypt(ctx context.Context, in io.Reader, out io.Writer, hdr *fileHeader, aead cipherAEAD, idx uint64, verbose bool) (bool, error) {
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

func decryptChunks(ctx context.Context, in io.Reader, out io.Writer, hdr *fileHeader, aead cipherAEAD, verbose bool) error {
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

func processOneRotate(ctx context.Context, in io.ReadSeeker, out io.Writer, origHdr *fileHeader, oldAEAD cipherAEAD, newHdr *fileHeader, newAEAD cipherAEAD, idx uint64, verbose bool) (bool, error) {
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
		return true, fmt.Errorf("decrypt chunk failed at idx %d: %w", idx, err)
	}
	newNonce := make([]byte, newHdr.NonceSize)
	if _, err = io.ReadFull(rand.Reader, newNonce); err != nil {
		return true, fmt.Errorf("new nonce gen: %w", err)
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

func rotateChunks(ctx context.Context, in io.ReadSeeker, out io.Writer, origHdr *fileHeader, oldAEAD cipherAEAD, newHdr *fileHeader, newAEAD cipherAEAD, verbose bool) error {
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

/*** High-level helpers ***/

func buildHeaderAndKeysForEncrypt(password []byte, chunkSize uint32, argonTime, argonMem uint32, argonThreads uint8, keyVersion uint32) (*fileHeader, []byte, []byte, error) {
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
	master := deriveMasterKeyArgon(password, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	encKey, macKey, err := deriveEncAndMacKeys(master)
	zero(master)
	if err != nil {
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

func encryptFile(ctx context.Context, inPath, outPath string, force bool, chunkSize uint32, argonTime, argonMem uint32, argonThreads uint8, keyVersion uint32, verbose bool) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	pw1 := readPasswordPrompt("Password: ")
	if len(pw1) == 0 {
		zero(pw1)
		return errors.New("empty password not allowed")
	}
	pw2 := readPasswordPrompt("Confirm password: ")
	if !secureCompare(pw1, pw2) {
		zero(pw1)
		zero(pw2)
		return errors.New("passwords do not match")
	}
	zero(pw2)

	hdr, encKey, macKey, err := buildHeaderAndKeysForEncrypt(pw1, chunkSize, argonTime, argonMem, argonThreads, keyVersion)
	zero(pw1)
	if err != nil {
		return err
	}
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
	if _, err = io.ReadFull(in, hdrBytes); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	var hdr fileHeader
	if err = parseHeaderFromBytes(hdrBytes, &hdr); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	if string(bytes.TrimRight(hdr.Magic[:], "\x00")) != MagicString {
		return errors.New("invalid magic")
	}

	pw := readPasswordPrompt("Password: ")
	defer zero(pw)
	master := deriveMasterKeyArgon(pw, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	encKey, macKey, err := deriveEncAndMacKeys(master)
	zero(master)
	if err != nil {
		zero(pw)
		return fmt.Errorf("derive keys: %w", err)
	}
	zero(pw)

	expected, err := computeHeaderHMAC(&hdr, macKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return fmt.Errorf("compute header mac: %w", err)
	}
	if !hmac.Equal(expected, hdr.HeaderMAC[:]) {
		zero(encKey)
		zero(macKey)
		return errors.New("wrong password or corrupted header")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return fmt.Errorf("init aead: %w", err)
	}
	defer zero(encKey)
	defer zero(macKey)

	writer := func(f *os.File) error {
		return decryptChunks(ctx, in, f, &hdr, aead, verbose)
	}
	dir := filepath.Dir(outPath)
	return atomicWriteReplace(dir, outPath, writer, force)
}

func prepareRotationKeys(pwNew []byte, newArgonTime, newArgonMem uint32, newArgonThreads uint8) (*fileHeader, []byte, []byte, error) {
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
	master := deriveMasterKeyArgon(pwNew, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	encKey, macKey, err := deriveEncAndMacKeys(master)
	zero(master)
	if err != nil {
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

func rotateFile(ctx context.Context, inPath, outPath string, force bool, newArgonTime, newArgonMem uint32, newArgonThreads uint8, newKeyVersion uint32, verbose bool) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	hdrBytes := make([]byte, headerTotalSize)
	if _, err = io.ReadFull(in, hdrBytes); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	var origHdr fileHeader
	if err = parseHeaderFromBytes(hdrBytes, &origHdr); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	if string(bytes.TrimRight(origHdr.Magic[:], "\x00")) != MagicString {
		return errors.New("invalid magic")
	}

	pwOld := readPasswordPrompt("Current password: ")
	defer zero(pwOld)
	masterOld := deriveMasterKeyArgon(pwOld, origHdr.Salt[:], origHdr.ArgonTime, origHdr.ArgonMemory, origHdr.ArgonThreads)
	oldEncKey, oldMacKey, err := deriveEncAndMacKeys(masterOld)
	zero(masterOld)
	if err != nil {
		zero(pwOld)
		return fmt.Errorf("derive keys (old): %w", err)
	}
	zero(pwOld)

	expected, err := computeHeaderHMAC(&origHdr, oldMacKey)
	if err != nil {
		zero(oldEncKey)
		zero(oldMacKey)
		return fmt.Errorf("compute header mac (old): %w", err)
	}
	if !hmac.Equal(expected, origHdr.HeaderMAC[:]) {
		zero(oldEncKey)
		zero(oldMacKey)
		return errors.New("wrong password or corrupted header (old)")
	}

	pwNew1 := readPasswordPrompt("New password: ")
	if len(pwNew1) == 0 {
		zero(pwNew1)
		zero(oldEncKey)
		zero(oldMacKey)
		return errors.New("empty password not allowed")
	}
	pwNew2 := readPasswordPrompt("Confirm new password: ")
	if !secureCompare(pwNew1, pwNew2) {
		zero(pwNew1)
		zero(pwNew2)
		zero(oldEncKey)
		zero(oldMacKey)
		return errors.New("passwords do not match")
	}
	zero(pwNew2)

	newHdr, newEncKey, newMacKey, err := prepareRotationKeys(pwNew1, newArgonTime, newArgonMem, newArgonThreads)
	if err != nil {
		zero(pwNew1)
		zero(oldEncKey)
		zero(oldMacKey)
		return err
	}
	newHdr.KeyVersion = newKeyVersion
	newHdr.ChunkSize = origHdr.ChunkSize
	newHdr.NonceSize = origHdr.NonceSize
	zero(pwNew1)

	defer zero(oldEncKey)
	defer zero(oldMacKey)
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

/*** Header parsing ***/

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

/*** CLI & main ***/

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
	enc, dec, rot    bool
	in, out          string
	force            bool
	allowAbsolute    bool
	chunkSize        uint32
	argTime, argMem  uint32
	argThreads       uint8
	keyVersion       uint32
	verbose          bool
}

func parseFlags() (runConfig, error) {
	var cfg runConfig
	enc := flag.Bool("e", false, "encrypt")
	dec := flag.Bool("d", false, "decrypt")
	rot := flag.Bool("r", false, "rotate (re-encrypt with new password/params)")
	force := flag.Bool("force", false, "overwrite output if exists")
	allowAbs := flag.Bool("allow-absolute", false, "allow writing output outside current working directory")
	chunkSizeFlag := flag.Uint("chunk-size", defaultChunkSize, fmt.Sprintf("chunk size in bytes (max %d)", maxChunkSize))
	preset := flag.String("preset", "default", "argon preset: default | high | low")
	argonTimeFlag := flag.Uint("argon-time", 0, "override argon time (optional)")
	argonMemFlag := flag.Uint("argon-memory", 0, "override argon memory (KiB) (optional)")
	argonThreadsFlag := flag.Uint("argon-threads", 0, "override argon threads (optional)")
	keyVersionFlag := flag.Uint("key-version", 1, "key version to write into header (rotate/encrypt)")
	verbose := flag.Bool("v", false, "verbose progress output")
	flag.Parse()

	if (*enc && *dec) || (*enc && *rot) || (*dec && *rot) || (!*enc && !*dec && !*rot) || flag.NArg() != 2 {
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
	in := flag.Arg(0)
	out := flag.Arg(1)
	if strings.TrimSpace(in) == "" || strings.TrimSpace(out) == "" {
		return cfg, errors.New("infile and outfile must be specified")
	}
	cfg.in = in
	cfg.out = out

	argTime, argMem, argThreads, err := parsePreset(*preset)
	if err != nil {
		return cfg, fmt.Errorf("preset parse: %w", err)
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
	if absIn == absOut && !cfg.force {
		return errors.New("input and output are the same path; use --force")
	}
	if cfg.chunkSize == 0 || cfg.chunkSize > maxChunkSize {
		return fmt.Errorf("invalid chunk size, must be 1..%d", maxChunkSize)
	}

	if cfg.enc {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Encrypting %s -> %s ...\n", absIn, absOut)
			fmt.Fprintf(os.Stderr, "Argon2: time=%d memory=%d KiB threads=%d chunk=%d\n", cfg.argTime, cfg.argMem, cfg.argThreads, cfg.chunkSize)
		}
		return encryptFile(ctx, absIn, absOut, cfg.force, cfg.chunkSize, cfg.argTime, cfg.argMem, cfg.argThreads, cfg.keyVersion, cfg.verbose)
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
			fmt.Fprintf(os.Stderr, "New Argon2: time=%d memory=%d KiB threads=%d\n", cfg.argTime, cfg.argMem, cfg.argThreads)
		}
		return rotateFile(ctx, absIn, absOut, cfg.force, cfg.argTime, cfg.argMem, cfg.argThreads, cfg.keyVersion, cfg.verbose)
	}
	return errors.New("no operation")
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
	if err = runOperation(ctx, cfg); err != nil {
		die(err)
	}

	if atomic.LoadInt32(&cancelled) == 1 {
		die(errors.New("operation cancelled"))
	}

	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "Done in %s (goos=%s goarch=%s)\n", time.Since(start), runtime.GOOS, runtime.GOARCH)
	}
}
