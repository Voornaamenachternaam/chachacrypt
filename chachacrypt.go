/*
Package main implements chachacrypt, a password-based file encryption tool
using Argon2id and XChaCha20-Poly1305 with authenticated headers and
streaming chunked I/O.

Security properties:
- Confidentiality, integrity, tamper detection
- Wrong-password detection
- Memory-hard KDF
- Constant-memory streaming
- Cross-platform (Windows 11, Linux)

This file is intentionally verbose and explicit to maximize auditability.
*/
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

const (
	magicString = "CHACHACRYPT"
	formatVersion uint32 = 1

	defaultChunkSize = 1 << 20 // 1 MiB
	maxChunkSize     = 16 << 20

	nonceSizeXChaCha = chacha20poly1305.NonceSizeX

	saltSize = 16

	headerReservedSize = 32
	headerMACSize      = 32

	maxCTAbsolute = 1 << 30 // 1 GiB hard upper bound

	keyLen = 32
)

var (
	errWrongPassword = errors.New("wrong password or file corrupted")
	errSameFile      = errors.New("input and output are the same file; in-place operations are not supported")
)

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func mustReadRandom(b []byte) error {
	n, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return errors.New("short read from crypto/rand")
	}
	return nil
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		zero(pw)
		return nil, errors.New("empty password")
	}
	return pw, nil
}

func confirmPassword() ([]byte, error) {
	pw1, err := readPassword("Enter password: ")
	if err != nil {
		return nil, err
	}
	defer zero(pw1)

	pw2, err := readPassword("Confirm password: ")
	if err != nil {
		return nil, err
	}
	defer zero(pw2)

	if !hmac.Equal(pw1, pw2) {
		return nil, errors.New("passwords do not match")
	}

	out := make([]byte, len(pw1))
	copy(out, pw1)
	return out, nil
}

func validateArgon2Params(t uint32, mem uint32, threads uint8) error {
	const minTime = 2
	const minMemory = 32 * 1024 // 32 MiB in KiB units
	const minThreads = 1

	if t < minTime {
		return fmt.Errorf("Argon2 time too low (min %d)", minTime)
	}
	if mem < minMemory {
		return fmt.Errorf("Argon2 memory too low (min %d KiB)", minMemory)
	}
	maxThreads := uint8(runtime.NumCPU() * 2)
	if threads < minThreads || threads > maxThreads {
		return fmt.Errorf("Argon2 threads must be between %d and %d", minThreads, maxThreads)
	}
	return nil
}

type fileHeader struct {
	Magic        [16]byte
	Version      uint32
	KeyVersion   uint32
	ChunkSize    uint32
	NonceSize    uint32

	ArgonTime    uint32
	ArgonMemory uint32
	ArgonThreads uint8
	_            [3]byte // padding

	Salt        [saltSize]byte
	Reserved    [headerReservedSize]byte
	HeaderMAC   [headerMACSize]byte
}

const headerSize = 16 + 4*5 + 4 + saltSize + headerReservedSize + headerMACSize

func (h *fileHeader) encode(withMAC bool) []byte {
	buf := make([]byte, headerSize)
	off := 0

	copy(buf[off:], h.Magic[:])
	off += 16

	binary.BigEndian.PutUint32(buf[off:], h.Version)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], h.KeyVersion)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], h.ChunkSize)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], h.NonceSize)
	off += 4

	binary.BigEndian.PutUint32(buf[off:], h.ArgonTime)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], h.ArgonMemory)
	off += 4
	buf[off] = h.ArgonThreads
	off += 4

	copy(buf[off:], h.Salt[:])
	off += saltSize

	copy(buf[off:], h.Reserved[:])
	off += headerReservedSize

	if withMAC {
		copy(buf[off:], h.HeaderMAC[:])
	}

	return buf
}

func parseHeader(b []byte) (*fileHeader, error) {
	if len(b) != headerSize {
		return nil, errors.New("invalid header size")
	}

	h := &fileHeader{}
	off := 0

	copy(h.Magic[:], b[off:off+16])
	off += 16

	h.Version = binary.BigEndian.Uint32(b[off:])
	off += 4
	h.KeyVersion = binary.BigEndian.Uint32(b[off:])
	off += 4
	h.ChunkSize = binary.BigEndian.Uint32(b[off:])
	off += 4
	h.NonceSize = binary.BigEndian.Uint32(b[off:])
	off += 4

	h.ArgonTime = binary.BigEndian.Uint32(b[off:])
	off += 4
	h.ArgonMemory = binary.BigEndian.Uint32(b[off:])
	off += 4
	h.ArgonThreads = b[off]
	off += 4

	copy(h.Salt[:], b[off:off+saltSize])
	off += saltSize

	copy(h.Reserved[:], b[off:off+headerReservedSize])
	off += headerReservedSize

	copy(h.HeaderMAC[:], b[off:off+headerMACSize])

	return h, nil
}

func validateHeader(h *fileHeader) error {
	if !hmac.Equal(bytes.TrimRight(h.Magic[:], "\x00"), []byte(magicString)) {
		return errors.New("invalid magic")
	}
	if h.Version != formatVersion {
		return fmt.Errorf("unsupported version %d", h.Version)
	}
	if h.ChunkSize == 0 || h.ChunkSize > maxChunkSize {
		return errors.New("invalid chunk size")
	}
	if h.NonceSize != nonceSizeXChaCha {
		return errors.New("invalid nonce size")
	}
	if err := validateArgon2Params(h.ArgonTime, h.ArgonMemory, h.ArgonThreads); err != nil {
		return err
	}
	for _, b := range h.Reserved {
		if b != 0 {
			return errors.New("reserved bytes not zero")
		}
	}
	return nil
}

func computeHeaderHMAC(h *fileHeader, macKey []byte) ([]byte, error) {
	tmp := *h
	for i := range tmp.HeaderMAC {
		tmp.HeaderMAC[i] = 0
	}

	mac := hmac.New(sha256.New, macKey)
	_, err := mac.Write(tmp.encode(false))
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func verifyHeaderHMAC(h *fileHeader, macKey []byte) error {
	expected, err := computeHeaderHMAC(h, macKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, h.HeaderMAC[:]) {
		return errors.New("header authentication failed")
	}
	return nil
}

const (
	masterKeySize = 32
	encKeySize    = 32
	macKeySize    = 32

	hkdfInfoEnc = "chachacrypt:enc"
	hkdfInfoMAC = "chachacrypt:mac"
	hkdfInfoAux = "chachacrypt:aux"
)

func validateArgon2Params(t, mem uint32, threads uint8) error {
	const minTime = 2
	const minMemory = 32 * 1024 // 32 MiB in KiB units
	const minThreads = 1

	if t < minTime {
		return fmt.Errorf("argon2 time too low (min %d)", minTime)
	}
	if mem < minMemory {
		return fmt.Errorf("argon2 memory too low (min %d KiB)", minMemory)
	}
	maxThreads := uint8(runtime.NumCPU() * 2)
	if threads < minThreads || threads > maxThreads {
		return fmt.Errorf("argon2 threads out of range")
	}
	return nil
}

func deriveMasterKeyArgon(password, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, t, mem, threads, masterKeySize)
}

func deriveKeysHKDF(master []byte) (encKey, macKey, auxKey []byte, err error) {
	hash := sha256.New

	encKey = make([]byte, encKeySize)
	if _, err = hkdf.Expand(hash, master, []byte(hkdfInfoEnc)).Read(encKey); err != nil {
		return nil, nil, nil, err
	}

	macKey = make([]byte, macKeySize)
	if _, err = hkdf.Expand(hash, master, []byte(hkdfInfoMAC)).Read(macKey); err != nil {
		zero(encKey)
		return nil, nil, nil, err
	}

	auxKey = make([]byte, encKeySize)
	if _, err = hkdf.Expand(hash, master, []byte(hkdfInfoAux)).Read(auxKey); err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, err
	}

	return encKey, macKey, auxKey, nil
}

func buildHeaderAndKeysForEncrypt(
	password []byte,
	chunkSize uint32,
	argonTime uint32,
	argonMem uint32,
	argonThreads uint8,
	keyVersion uint32,
) (*fileHeader, []byte, []byte, error) {

	if err := validateArgon2Params(argonTime, argonMem, argonThreads); err != nil {
		return nil, nil, nil, err
	}

	hdr := &fileHeader{}
	copy(hdr.Magic[:], []byte(magicString))
	hdr.Version = formatVersion
	hdr.KeyVersion = keyVersion
	hdr.ChunkSize = chunkSize
	hdr.NonceSize = nonceSizeXChaCha
	hdr.ArgonTime = argonTime
	hdr.ArgonMemory = argonMem
	hdr.ArgonThreads = argonThreads

	if _, err := io.ReadFull(rand.Reader, hdr.Salt[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("salt generation failed: %w", err)
	}

	master := deriveMasterKeyArgon(password, hdr.Salt[:], argonTime, argonMem, argonThreads)
	defer zero(master)

	encKey, macKey, _, err := deriveKeysHKDF(master)
	if err != nil {
		return nil, nil, nil, err
	}

	mac, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		zero(encKey)
		zero(macKey)
		return nil, nil, nil, err
	}
	copy(hdr.HeaderMAC[:], mac)

	return hdr, encKey, macKey, nil
}

func prepareRotationKeys(
	password []byte,
	argonTime uint32,
	argonMem uint32,
	argonThreads uint8,
) (*fileHeader, []byte, []byte, error) {

	if err := validateArgon2Params(argonTime, argonMem, argonThreads); err != nil {
		return nil, nil, nil, err
	}

	hdr := &fileHeader{}
	copy(hdr.Magic[:], []byte(magicString))
	hdr.Version = formatVersion
	hdr.ArgonTime = argonTime
	hdr.ArgonMemory = argonMem
	hdr.ArgonThreads = argonThreads
	hdr.NonceSize = nonceSizeXChaCha

	if _, err := io.ReadFull(rand.Reader, hdr.Salt[:]); err != nil {
		return nil, nil, nil, err
	}

	master := deriveMasterKeyArgon(password, hdr.Salt[:], argonTime, argonMem, argonThreads)
	defer zero(master)

	encKey, macKey, _, err := deriveKeysHKDF(master)
	if err != nil {
		return nil, nil, nil, err
	}

	return hdr, encKey, macKey, nil
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func newXChaCha20Poly1305(key []byte) (cipherAEAD, error) {
	return chacha20poly1305.NewX(key)
}

func buildAAD(hdr *fileHeader, chunkIndex uint64) ([]byte, error) {
	hb, err := serializeHeaderCanonical(hdr, true)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 0, len(hb)+8)
	aad = append(aad, hb...)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], chunkIndex)
	aad = append(aad, idxBuf[:]...)
	return aad, nil
}

func writeChunkFrame(w io.Writer, nonce, ct []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(nonce))); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(ct))); err != nil {
		return err
	}
	if _, err := w.Write(ct); err != nil {
		return err
	}
	return nil
}

func readChunkFrame(r io.Reader) ([]byte, []byte, error) {
	var nNonce uint32
	if err := binary.Read(r, binary.BigEndian, &nNonce); err != nil {
		return nil, nil, err
	}
	if nNonce == 0 || nNonce > 64 {
		return nil, nil, fmt.Errorf("invalid nonce length: %d", nNonce)
	}
	nonce := make([]byte, nNonce)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, nil, err
	}

	var nCT uint32
	if err := binary.Read(r, binary.BigEndian, &nCT); err != nil {
		return nil, nil, err
	}
	const maxReasonableCT = maxChunkSize + 128
	if nCT == 0 || nCT > maxReasonableCT || nCT > maxCTSize {
		return nil, nil, fmt.Errorf("ciphertext too large: %d", nCT)
	}
	ct := make([]byte, nCT)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

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
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return true, rerr
	}
	if n == 0 && rerr == io.EOF {
		return true, nil
	}

	nonce := make([]byte, hdr.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return true, err
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	ct := aead.Seal(nil, nonce, buf[:n], aad)

	if err := writeChunkFrame(out, nonce, ct); err != nil {
		return true, err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Encrypted chunk %d (%d bytes)\n", idx, n)
	}

	return false, nil
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

	nonce, ct, err := readChunkFrame(in)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return true, err
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return true, errors.New("decryption failed (wrong password or tampered data)")
	}

	if _, err := out.Write(pt); err != nil {
		zero(pt)
		return true, err
	}
	zero(pt)

	if verbose {
		fmt.Fprintf(os.Stderr, "Decrypted chunk %d (%d bytes)\n", idx, len(pt))
	}

	return false, nil
}

func serializeHeaderCanonical(hdr *fileHeader, zeroMAC bool) ([]byte, error) {
	buf := new(bytes.Buffer)

	write := func(v any) error {
		return binary.Write(buf, binary.BigEndian, v)
	}

	if _, err := buf.Write(hdr.Magic[:]); err != nil {
		return nil, err
	}
	if err := write(hdr.Version); err != nil {
		return nil, err
	}
	if err := write(hdr.KeyVersion); err != nil {
		return nil, err
	}
	if err := write(hdr.ArgonTime); err != nil {
		return nil, err
	}
	if err := write(hdr.ArgonMemory); err != nil {
		return nil, err
	}
	if err := write(hdr.ArgonThreads); err != nil {
		return nil, err
	}
	if _, err := buf.Write(hdr.Salt[:]); err != nil {
		return nil, err
	}
	if err := write(hdr.ChunkSize); err != nil {
		return nil, err
	}
	if err := write(hdr.NonceSize); err != nil {
		return nil, err
	}
	if _, err := buf.Write(hdr.Reserved[:]); err != nil {
		return nil, err
	}

	if zeroMAC {
		var zero [headerMACSize]byte
		if _, err := buf.Write(zero[:]); err != nil {
			return nil, err
		}
	} else {
		if _, err := buf.Write(hdr.HeaderMAC[:]); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func parseHeaderFromBytes(b []byte, hdr *fileHeader) error {
	r := bytes.NewReader(b)

	read := func(v any) error {
		return binary.Read(r, binary.BigEndian, v)
	}

	if _, err := io.ReadFull(r, hdr.Magic[:]); err != nil {
		return err
	}
	if err := read(&hdr.Version); err != nil {
		return err
	}
	if err := read(&hdr.KeyVersion); err != nil {
		return err
	}
	if err := read(&hdr.ArgonTime); err != nil {
		return err
	}
	if err := read(&hdr.ArgonMemory); err != nil {
		return err
	}
	if err := read(&hdr.ArgonThreads); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, hdr.Salt[:]); err != nil {
		return err
	}
	if err := read(&hdr.ChunkSize); err != nil {
		return err
	}
	if err := read(&hdr.NonceSize); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, hdr.Reserved[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, hdr.HeaderMAC[:]); err != nil {
		return err
	}

	return nil
}

func validateHeader(hdr *fileHeader) error {
	if !secureCompare(hdr.Magic[:], []byte(MagicString)) {
		return errors.New("invalid magic")
	}
	if hdr.Version != fileVersion {
		return fmt.Errorf("unsupported version %d", hdr.Version)
	}
	if err := validateArgon2Params(hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads); err != nil {
		return err
	}
	if hdr.ChunkSize == 0 || hdr.ChunkSize > maxChunkSize {
		return errors.New("invalid chunk size")
	}
	if hdr.NonceSize != nonceSize {
		return errors.New("invalid nonce size")
	}
	for _, b := range hdr.Reserved {
		if b != 0 {
			return errors.New("reserved bytes not zero")
		}
	}
	return nil
}

func computeHeaderHMAC(hdr *fileHeader, macKey []byte) ([]byte, error) {
	hb, err := serializeHeaderCanonical(hdr, true)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, macKey)
	if _, err := h.Write(hb); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func verifyHeaderHMAC(hdr *fileHeader, macKey []byte) error {
	mac, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		return err
	}
	if !secureCompare(mac, hdr.HeaderMAC[:]) {
		return errors.New("header authentication failed")
	}
	return nil
}

func writeChunkFrame(w io.Writer, nonce, ct []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(nonce))); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(ct))); err != nil {
		return err
	}
	if _, err := w.Write(ct); err != nil {
		return err
	}
	return nil
}

func readChunkFrame(r io.Reader) ([]byte, []byte, error) {
	var nNonce uint32
	if err := binary.Read(r, binary.BigEndian, &nNonce); err != nil {
		return nil, nil, err
	}
	if nNonce == 0 || nNonce > 64 {
		return nil, nil, errors.New("invalid nonce length")
	}
	nonce := make([]byte, nNonce)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, nil, err
	}

	var nCT uint32
	if err := binary.Read(r, binary.BigEndian, &nCT); err != nil {
		return nil, nil, err
	}
	const maxReasonableCT = maxChunkSize + 128
	if nCT == 0 || nCT > maxReasonableCT {
		return nil, nil, errors.New("ciphertext length invalid")
	}
	ct := make([]byte, nCT)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func processOneEncrypt(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipher.AEAD,
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
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return true, rerr
	}
	if n == 0 && rerr == io.EOF {
		return true, nil
	}

	nonce := make([]byte, hdr.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return true, err
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	ct := aead.Seal(nil, nonce, buf[:n], aad)
	if err := writeChunkFrame(out, nonce, ct); err != nil {
		return true, err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Encrypted chunk %d (%d bytes)\n", idx, n)
	}

	return false, nil
}

func processOneDecrypt(
	ctx context.Context,
	in io.Reader,
	out io.Writer,
	hdr *fileHeader,
	aead cipher.AEAD,
	idx uint64,
	verbose bool,
) (bool, error) {

	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}

	nonce, ct, err := readChunkFrame(in)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return true, err
	}

	aad, err := buildAAD(hdr, idx)
	if err != nil {
		return true, err
	}

	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return true, errors.New("decryption failed (wrong password or tampered data)")
	}

	if _, err := out.Write(pt); err != nil {
		zero(pt)
		return true, err
	}
	zero(pt)

	if verbose {
		fmt.Fprintf(os.Stderr, "Decrypted chunk %d (%d bytes)\n", idx, len(ct))
	}

	return false, nil
}

func processOneRotate(
	ctx context.Context,
	in io.ReadSeeker,
	out io.Writer,
	origHdr *fileHeader,
	oldAEAD cipher.AEAD,
	newHdr *fileHeader,
	newAEAD cipher.AEAD,
	idx uint64,
	verbose bool,
) (bool, error) {

	select {
	case <-ctx.Done():
		return true, ctx.Err()
	default:
	}

	nonce, ct, err := readChunkFrame(in)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return true, err
	}

	aadOld, err := buildAAD(origHdr, idx)
	if err != nil {
		return true, err
	}

	pt, err := oldAEAD.Open(nil, nonce, ct, aadOld)
	if err != nil {
		return true, errors.New("decryption failed during rotation")
	}

	newNonce := make([]byte, newHdr.NonceSize)
	if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
		zero(pt)
		return true, err
	}

	aadNew, err := buildAAD(newHdr, idx)
	if err != nil {
		zero(pt)
		return true, err
	}

	newCT := newAEAD.Seal(nil, newNonce, pt, aadNew)
	zero(pt)

	if err := writeChunkFrame(out, newNonce, newCT); err != nil {
		return true, err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Rotated chunk %d\n", idx)
	}

	return false, nil
}

func encryptFile(
	ctx context.Context,
	inPath, outPath string,
	chunkSize uint32,
	argonTime, argonMem uint32,
	argonThreads uint8,
	keyVersion uint32,
	verbose bool,
) error {

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

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

	hdr, encKey, macKey, err := buildHeaderAndKeysForEncrypt(
		pw1, chunkSize, argonTime, argonMem, argonThreads, keyVersion,
	)
	if err != nil {
		return err
	}
	defer zero(encKey)
	defer zero(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	hdrMAC, err := computeHeaderHMAC(hdr, macKey)
	if err != nil {
		return err
	}
	copy(hdr.HeaderMAC[:], hdrMAC)

	return atomicWriteReplace("", outPath, func(out *os.File) error {
		hdrBytes, err := serializeHeaderCanonical(hdr)
		if err != nil {
			return err
		}
		if _, err := out.Write(hdrBytes); err != nil {
			return err
		}

		buf := make([]byte, hdr.ChunkSize)
		var idx uint64

		for {
			done, err := processOneEncrypt(ctx, in, out, hdr, aead, buf, idx, verbose)
			if err != nil {
				return err
			}
			if done {
				break
			}
			idx++
		}
		return nil
	}, false)
}

func decryptFile(
	ctx context.Context,
	inPath, outPath string,
	verbose bool,
) error {

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	hdrBytes := make([]byte, headerSize)
	if _, err := io.ReadFull(in, hdrBytes); err != nil {
		return err
	}

	var hdr fileHeader
	if err := parseHeaderFromBytes(hdrBytes, &hdr); err != nil {
		return err
	}
	if err := validateHeader(&hdr); err != nil {
		return err
	}

	pw := readPasswordPrompt("Password: ")
	defer zero(pw)

	master := deriveMasterKeyArgon(pw, hdr.Salt[:], hdr.ArgonTime, hdr.ArgonMemory, hdr.ArgonThreads)
	defer zero(master)

	encKey, macKey, err := deriveEncAndMacKeys(master)
	if err != nil {
		return err
	}
	defer zero(encKey)
	defer zero(macKey)

	if !verifyHeaderHMAC(&hdr, macKey) {
		return errors.New("header authentication failed (wrong password or tampered file)")
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	return atomicWriteReplace("", outPath, func(out *os.File) error {
		var idx uint64
		for {
			done, err := processOneDecrypt(ctx, in, out, &hdr, aead, idx, verbose)
			if err != nil {
				return err
			}
			if done {
				break
			}
			idx++
		}
		return nil
	}, false)
}

func rotateFile(
	ctx context.Context,
	inPath, outPath string,
	newArgonTime, newArgonMem uint32,
	newArgonThreads uint8,
	newKeyVersion uint32,
	verbose bool,
) error {

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	hdrBytes := make([]byte, headerSize)
	if _, err := io.ReadFull(in, hdrBytes); err != nil {
		return err
	}

	var origHdr fileHeader
	if err := parseHeaderFromBytes(hdrBytes, &origHdr); err != nil {
		return err
	}
	if err := validateHeader(&origHdr); err != nil {
		return err
	}

	pwOld := readPasswordPrompt("Current password: ")
	defer zero(pwOld)

	masterOld := deriveMasterKeyArgon(
		pwOld, origHdr.Salt[:],
		origHdr.ArgonTime, origHdr.ArgonMemory, origHdr.ArgonThreads,
	)
	defer zero(masterOld)

	oldEncKey, oldMacKey, err := deriveEncAndMacKeys(masterOld)
	if err != nil {
		return err
	}
	defer zero(oldEncKey)
	defer zero(oldMacKey)

	if !verifyHeaderHMAC(&origHdr, oldMacKey) {
		return errors.New("authentication failed (wrong password)")
	}

	oldAEAD, err := chacha20poly1305.NewX(oldEncKey)
	if err != nil {
		return err
	}

	pwNew1 := readPasswordPrompt("New password: ")
	defer zero(pwNew1)
	if len(pwNew1) == 0 {
		return errors.New("empty password not allowed")
	}

	pwNew2 := readPasswordPrompt("Confirm new password: ")
	defer zero(pwNew2)
	if !secureCompare(pwNew1, pwNew2) {
		return errors.New("passwords do not match")
	}

	newHdr, newEncKey, newMacKey, err := prepareRotationKeys(
		pwNew1, newArgonTime, newArgonMem, newArgonThreads,
	)
	if err != nil {
		return err
	}
	defer zero(newEncKey)
	defer zero(newMacKey)

	newHdr.KeyVersion = newKeyVersion
	newHdr.ChunkSize = origHdr.ChunkSize
	newHdr.NonceSize = origHdr.NonceSize

	newMAC, err := computeHeaderHMAC(newHdr, newMacKey)
	if err != nil {
		return err
	}
	copy(newHdr.HeaderMAC[:], newMAC)

	newAEAD, err := chacha20poly1305.NewX(newEncKey)
	if err != nil {
		return err
	}

	return atomicWriteReplace("", outPath, func(out *os.File) error {
		hdrBytes, err := serializeHeaderCanonical(newHdr)
		if err != nil {
			return err
		}
		if _, err := out.Write(hdrBytes); err != nil {
			return err
		}

		var idx uint64
		for {
			done, err := processOneRotate(
				ctx, in, out,
				&origHdr, oldAEAD,
				newHdr, newAEAD,
				idx, verbose,
			)
			if err != nil {
				return err
			}
			if done {
				break
			}
			idx++
		}
		return nil
	}, false)
}

func usage() {
	fmt.Fprintf(os.Stderr, `chachacrypt — password-based file encryption

Usage:
  chachacrypt encrypt   -in <file> -out <file> [options]
  chachacrypt decrypt   -in <file> -out <file>
  chachacrypt rotate    -in <file> -out <file> [options]

Options (encrypt / rotate):
  --argon default|high|low   Argon2id preset (default: default)
  --chunk-size <bytes>       Chunk size (default 1MiB, max 16MiB)
  --key-version <n>          Key version metadata
  --verbose                  Verbose progress

Presets:
  default: t=3, mem=128MiB, threads=4
  high:    t=4, mem=256MiB (resource intensive)
  low:     t=2, mem=32MiB  (prompted)

`)
	os.Exit(2)
}

type argonPreset struct {
	t uint32
	m uint32
	p uint8
}

func resolveArgonPreset(name string) (argonPreset, error) {
	switch name {
	case "default":
		return argonPreset{3, 128 * 1024, 4}, nil
	case "high":
		return argonPreset{4, 256 * 1024, 4}, nil
	case "low":
		fmt.Fprintln(os.Stderr, "Warning: low Argon2 parameters reduce security.")
		if !promptYesNo("Continue?") {
			return argonPreset{}, errors.New("aborted")
		}
		return argonPreset{2, 32 * 1024, 2}, nil
	default:
		return argonPreset{}, fmt.Errorf("unknown Argon2 preset: %s", name)
	}
}

func safeAbsPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func ensureDistinctPaths(inPath, outPath string) error {
	inStat, err := os.Stat(inPath)
	if err != nil {
		return err
	}
	outStat, err := os.Stat(outPath)
	if err == nil && os.SameFile(inStat, outStat) {
		return errors.New("input and output paths refer to the same file")
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	ctx := context.Background()
	cmd := os.Args[1]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	inPath := fs.String("in", "", "input file")
	outPath := fs.String("out", "", "output file")
	argonPresetName := fs.String("argon", "default", "argon2 preset")
	chunkSize := fs.Uint("chunk-size", defaultChunkSize, "chunk size bytes")
	keyVersion := fs.Uint("key-version", 1, "key version")
	verbose := fs.Bool("verbose", false, "verbose")

	if err := fs.Parse(os.Args[2:]); err != nil {
		die(err)
	}

	if *inPath == "" || *outPath == "" {
		usage()
	}

	inAbs, err := safeAbsPath(*inPath)
	if err != nil {
		die(err)
	}
	outAbs, err := safeAbsPath(*outPath)
	if err != nil {
		die(err)
	}

	if err := ensureDistinctPaths(inAbs, outAbs); err != nil {
		die(err)
	}

	switch cmd {
	case "encrypt":
		preset, err := resolveArgonPreset(*argonPresetName)
		if err != nil {
			die(err)
		}
		if *chunkSize == 0 || *chunkSize > maxChunkSize {
			die(fmt.Errorf("invalid chunk size"))
		}
		err = encryptFile(
			ctx,
			inAbs, outAbs,
			uint32(*chunkSize),
			preset.t, preset.m, preset.p,
			uint32(*keyVersion),
			*verbose,
		)
	case "decrypt":
		err = decryptFile(ctx, inAbs, outAbs, *verbose)
	case "rotate":
		preset, err := resolveArgonPreset(*argonPresetName)
		if err != nil {
			die(err)
		}
		err = rotateFile(
			ctx,
			inAbs, outAbs,
			preset.t, preset.m, preset.p,
			uint32(*keyVersion),
			*verbose,
		)
	default:
		usage()
		return
	}

	if err != nil {
		die(err)
	}
}
