package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var fileMagicV2 = [8]byte{'C', 'C', 'R', 'Y', 'P', 'T', 'V', '2'}

const (
	FileVersionV1       = uint32(1)
	FileVersionV2       = uint32(2)
	DefaultSaltSize     = 32
	DefaultKeySize      = 32
	IntegritySize       = 32
	DefaultChunkSize    = 1 << 20
	DefaultArgonTime    = 3
	DefaultArgonMem     = 131072
	DefaultArgonThreads = 4
	MacKeyLen           = 32
)

var sink byte

type SecureBuffer struct {
	b []byte
}

func NewSecureBuffer(size int) *SecureBuffer {
	return &SecureBuffer{b: make([]byte, size)}
}

func NewSecureBufferFromBytes(src []byte) *SecureBuffer {
	b := make([]byte, len(src))
	copy(b, src)
	return &SecureBuffer{b: b}
}

func (s *SecureBuffer) Close() {
	if s == nil || s.b == nil {
		return
	}
	zeroBytes(s.b)
	s.b = nil
}

func (s *SecureBuffer) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

func (s *SecureBuffer) Len() int {
	if s == nil {
		return 0
	}
	return len(s.b)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	if len(b) > 0 {
		sink = b[0]
	}
	runtime.KeepAlive(b)
}

type FileHeader struct {
	Version      uint32
	KeyVersion   uint32
	ArgonTime    uint32
	ArgonMem     uint32
	ArgonThreads uint8
	KeySize      uint16
	SaltSize     uint16
	ChunkSize    uint32
	reserved     uint32
	Integrity    [IntegritySize]byte
}

var (
	saltMu    sync.Mutex
	saltCache = make(map[string][]byte)
)

func recordSalt(salt []byte, ttl time.Duration) error {
	hex := fmt.Sprintf("%x", salt)

	saltMu.Lock()
	defer saltMu.Unlock()
	if _, ok := saltCache[hex]; ok {
		return fmt.Errorf("salt reuse detected in current process")
	}
	cp := make([]byte, len(salt))
	copy(cp, salt)
	saltCache[hex] = cp

	go func(key string, out []byte) {
		timer := time.NewTimer(ttl)
		<-timer.C
		saltMu.Lock()
		if v, ok := saltCache[key]; ok {
			for i := range v {
				v[i] = 0
			}
			delete(saltCache, key)
		}
		saltMu.Unlock()
	}(hex, cp)

	return nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func computeHeaderHMACWithKey(header FileHeader, macKey []byte) ([IntegritySize]byte, error) {
	hc := header
	for i := range hc.Integrity {
		hc.Integrity[i] = 0
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &hc); err != nil {
		return [IntegritySize]byte{}, err
	}
	mac := hmac.New(sha256.New, macKey)
	if _, err := mac.Write(buf.Bytes()); err != nil {
		return [IntegritySize]byte{}, err
	}
	sum := mac.Sum(nil)
	var out [IntegritySize]byte
	copy(out[:], sum)
	zeroBytes(buf.Bytes())
	return out, nil
}

func computeHeaderHMACWithSalt(header FileHeader, salt []byte) ([IntegritySize]byte, error) {
	hc := header
	for i := range hc.Integrity {
		hc.Integrity[i] = 0
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &hc); err != nil {
		return [IntegritySize]byte{}, err
	}
	mac := hmac.New(sha256.New, salt)
	if _, err := mac.Write(buf.Bytes()); err != nil {
		return [IntegritySize]byte{}, err
	}
	sum := mac.Sum(nil)
	var out [IntegritySize]byte
	copy(out[:], sum)
	zeroBytes(buf.Bytes())
	return out, nil
}

func verifyHeaderHMACWithKey(header FileHeader, macKey []byte) error {
	expected, err := computeHeaderHMACWithKey(header, macKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected[:], header.Integrity[:]) {
		return errors.New("header integrity failure (macKey)")
	}
	return nil
}

func verifyHeaderHMACWithSalt(header FileHeader, salt []byte) error {
	expected, err := computeHeaderHMACWithSalt(header, salt)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected[:], header.Integrity[:]) {
		return errors.New("header integrity failure (salt)")
	}
	return nil
}

func deriveKeys(password []byte, salt []byte, header FileHeader, encKeyLen int, macKeyLen int) (encKey *SecureBuffer, macKey []byte, err error) {
	total := encKeyLen + macKeyLen
	timeParam := uint32(header.ArgonTime)
	memParam := uint32(header.ArgonMem)
	par := uint8(header.ArgonThreads)
	if par == 0 {
		par = DefaultArgonThreads
	}

	derived := argon2.IDKey(password, salt, timeParam, memParam, par, uint32(total))
	if len(derived) < total {
		zeroBytes(derived)
		return nil, nil, errors.New("argon2 derived too-short output")
	}

	enc := NewSecureBuffer(encKeyLen)
	copy(enc.Bytes(), derived[:encKeyLen])
	mac := make([]byte, macKeyLen)
	copy(mac, derived[encKeyLen:encKeyLen+macKeyLen])

	zeroBytes(derived)
	runtime.KeepAlive(derived)

	if _, err := chacha20poly1305.NewX(enc.Bytes()); err != nil {
		enc.Close()
		zeroBytes(mac)
		return nil, nil, fmt.Errorf("invalid AEAD key: %w", err)
	}

	return enc, mac, nil
}

func writeAll(w io.Writer, b []byte) error {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

func writeSalt(w io.Writer, salt []byte) error {
	if len(salt) > 0xFFFF {
		return errors.New("salt too large")
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(len(salt))); err != nil {
		return err
	}
	return writeAll(w, salt)
}

func readSalt(r io.Reader) ([]byte, error) {
	var l uint16
	if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
		return nil, err
	}
	if l == 0 {
		return nil, errors.New("salt length zero")
	}
	salt := make([]byte, int(l))
	if _, err := io.ReadFull(r, salt); err != nil {
		zeroBytes(salt)
		return nil, err
	}
	return salt, nil
}

func writeHeader(w io.Writer, header *FileHeader) error {
	return binary.Write(w, binary.LittleEndian, header)
}

func readHeader(r io.Reader) (FileHeader, error) {
	var hdr FileHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return FileHeader{}, err
	}
	return hdr, nil
}

func encryptFile(inPath, outPath string, password *SecureBuffer, cfg *EncryptConfig) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() {
		outFile.Close()
		if err != nil {
			_ = os.Remove(outPath)
		}
	}()

	if cfg.SaltSize <= 0 {
		cfg.SaltSize = DefaultSaltSize
	}
	if cfg.KeySize <= 0 {
		cfg.KeySize = DefaultKeySize
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.ArgonTime <= 0 {
		cfg.ArgonTime = DefaultArgonTime
	}
	if cfg.ArgonMem <= 0 {
		cfg.ArgonMem = DefaultArgonMem
	}
	if cfg.ArgonThreads <= 0 {
		cfg.ArgonThreads = DefaultArgonThreads
	}

	salt, err := randBytes(cfg.SaltSize)
	if err != nil {
		return err
	}
	_ = recordSalt(salt, time.Hour)

	var header FileHeader
	header.Version = FileVersionV2
	header.KeyVersion = 1
	header.ArgonTime = uint32(cfg.ArgonTime)
	header.ArgonMem = uint32(cfg.ArgonMem)
	header.ArgonThreads = uint8(cfg.ArgonThreads)
	header.KeySize = uint16(cfg.KeySize)
	header.SaltSize = uint16(cfg.SaltSize)
	header.ChunkSize = uint32(cfg.ChunkSize)

	encKey, macKey, err := deriveKeys(password.Bytes(), salt, header, int(header.KeySize), MacKeyLen)
	if err != nil {
		return err
	}
	defer encKey.Close()
	defer func() { zeroBytes(macKey) }()

	integrity, err := computeHeaderHMACWithKey(header, macKey)
	if err != nil {
		return err
	}
	header.Integrity = integrity

	if _, err := outFile.Write(fileMagicV2[:]); err != nil {
		return err
	}
	if err := writeSalt(outFile, salt); err != nil {
		return err
	}
	if err := writeHeader(outFile, &header); err != nil {
		return err
	}

	if err := streamEncryptInto(encKey.Bytes(), inFile, outFile, int(header.ChunkSize)); err != nil {
		return err
	}

	encKey.Close()
	zeroBytes(macKey)
	zeroBytes(salt)
	return nil
}

func decryptFile(inPath, outPath string, password *SecureBuffer) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() {
		outFile.Close()
		if err != nil {
			_ = os.Remove(outPath)
		}
	}()

	var magic [8]byte
	if _, err := io.ReadFull(inFile, magic[:]); err != nil {
		return err
	}

	if bytes.Equal(magic[:], fileMagicV2[:]) {
		if err := handleDecryptV2(inFile, outFile, password); err != nil {
			return err
		}
		return nil
	}

	if _, err := inFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := handleDecryptV1(inFile, outFile, password); err != nil {
		return err
	}
	return nil
}

func handleDecryptV2(inFile *os.File, outFile *os.File, password *SecureBuffer) error {
	salt, err := readSalt(inFile)
	if err != nil {
		return err
	}
	defer func() { zeroBytes(salt) }()

	header, err := readHeader(inFile)
	if err != nil {
		return err
	}

	if header.Version != FileVersionV2 {
		return fmt.Errorf("unexpected file version: %d (expected v2)", header.Version)
	}
	if int(header.SaltSize) != len(salt) {
		return fmt.Errorf("salt size mismatch: header=%d actual=%d", header.SaltSize, len(salt))
	}

	encKey, macKey, err := deriveKeys(password.Bytes(), salt, header, int(header.KeySize), MacKeyLen)
	if err != nil {
		return err
	}
	defer encKey.Close()
	defer func() { zeroBytes(macKey) }()

	if err := verifyHeaderHMACWithKey(header, macKey); err != nil {
		return err
	}

	if err := streamDecryptInto(encKey.Bytes(), inFile, outFile, int(header.ChunkSize)); err != nil {
		return err
	}
	return nil
}

func handleDecryptV1(inFile *os.File, outFile *os.File, password *SecureBuffer) error {
	header, err := readHeader(inFile)
	if err != nil {
		return err
	}

	salt, err := readSalt(inFile)
	if err != nil {
		return err
	}
	defer func() { zeroBytes(salt) }()

	if err := verifyHeaderHMACWithSalt(header, salt); err != nil {
		return err
	}

	encKey, macKey, err := deriveKeys(password.Bytes(), salt, header, int(header.KeySize), MacKeyLen)
	if err != nil {
		return err
	}
	defer encKey.Close()
	defer func() { zeroBytes(macKey) }()

	if err := streamDecryptInto(encKey.Bytes(), inFile, outFile, int(header.ChunkSize)); err != nil {
		return err
	}
	return nil
}

func streamEncryptInto(encKey []byte, in io.Reader, out io.Writer, chunkSize int) error {
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}
	nonceSize := chacha20poly1305.NonceSizeX

	buf := make([]byte, chunkSize)
	for {
		n, rerr := io.ReadFull(in, buf)
		if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
			return rerr
		}
		plaintext := buf[:n]

		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			zeroBytes(nonce)
			return err
		}
		ciphertext := aead.Seal(nil, nonce, plaintext, nil)

		if err := binary.Write(out, binary.LittleEndian, uint32(len(ciphertext))); err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			return err
		}
		if err := writeAll(out, nonce); err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			return err
		}
		if err := writeAll(out, ciphertext); err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			return err
		}

		zeroBytes(nonce)
		zeroBytes(ciphertext)
		if rerr == io.ErrUnexpectedEOF || rerr == io.EOF {
			break
		}
	}
	zeroBytes(buf)
	return nil
}

func streamDecryptInto(encKey []byte, in io.Reader, out io.Writer, chunkSize int) error {
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}
	nonceSize := chacha20poly1305.NonceSizeX

	for {
		var clen uint32
		if err := binary.Read(in, binary.LittleEndian, &clen); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if clen == 0 || clen > uint32(1<<30) {
			return errors.New("invalid ciphertext length")
		}

		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(in, nonce); err != nil {
			zeroBytes(nonce)
			return err
		}
		ciphertext := make([]byte, clen)
		if _, err := io.ReadFull(in, ciphertext); err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			return err
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			return err
		}
		if _, err := writeAll(out, plaintext); err != nil {
			zeroBytes(nonce)
			zeroBytes(ciphertext)
			zeroBytes(plaintext)
			return err
		}

		zeroBytes(nonce)
		zeroBytes(ciphertext)
		zeroBytes(plaintext)
	}
}

type EncryptConfig struct {
	SaltSize     int
	KeySize      int
	ChunkSize    int
	ArgonTime    int
	ArgonMem     int
	ArgonThreads int
}

func DefaultEncryptConfig() *EncryptConfig {
	return &EncryptConfig{
		SaltSize:     DefaultSaltSize,
		KeySize:      DefaultKeySize,
		ChunkSize:    DefaultChunkSize,
		ArgonTime:    DefaultArgonTime,
		ArgonMem:     DefaultArgonMem,
		ArgonThreads: DefaultArgonThreads,
	}
}
