package main

import (
	"bytes"
	"context"
	"crypto/cipher"
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
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	MagicNumber         = "CHACRYPT"
	FileVersion         = byte(2)
	defaultSalt         = 32
	defaultKey          = 32
	defaultNonce        = chacha20poly1305.NonceSizeX
	defaultArgonTime    = 6
	defaultArgonMemory  = 256 * 1024
	defaultArgonThreads = 2
	defaultChunkSize    = 64 * 1024

	maxArgonTime   = 1 << 12
	maxArgonMemory = 1 << 22
	maxChunkSize   = 1 << 22
	maxSaltSize    = 1 << 8
	maxKeySize     = 1 << 8

	entropyCheckSize = 4096
	minEntropyBits   = 7.5

	maxKeyVersion = 255
)

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type CSPRNGReader struct {
	entropyChecked atomic.Bool
}

func (r *CSPRNGReader) Read(p []byte) (n int, err error) {
	n, err = rand.Read(p)
	if n > 0 && !r.entropyChecked.Load() {
		if err := r.checkEntropy(p[:minInt(n, entropyCheckSize)]); err != nil {
			return 0, fmt.Errorf("entropy check failed: %w", err)
		}
		r.entropyChecked.Store(true)
	}
	return n, err
}

func (r *CSPRNGReader) checkEntropy(sample []byte) error {
	if len(sample) < entropyCheckSize/2 {
		return nil
	}
	freq := make(map[byte]int)
	for _, b := range sample {
		freq[b]++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(sample))
		entropy -= p * math.Log2(p)
	}
	maxPossible := math.Log2(math.Min(256.0, float64(len(sample))))
	if minEntropyBits > maxPossible {
		return fmt.Errorf("sample too small for required entropy")
	}
	if entropy < minEntropyBits {
		return fmt.Errorf("insufficient entropy")
	}
	return nil
}

var (
	csprng    = &CSPRNGReader{}
	saltCache = make(map[string][]byte)
	saltMu    sync.RWMutex
	saltWg    sync.WaitGroup
)

func sink(b []byte) {
	runtime.KeepAlive(b)
}

type FileHeader struct {
	Magic      [len(MagicNumber)]byte
	Version    byte
	ArgonTime  uint32
	ArgonMem   uint32
	ArgonUtil  uint8
	KeySize    uint32
	SaltSize   uint32
	NonceSize  uint32
	KeyVersion byte
	Timestamp  uint64
	Integrity  [32]byte
	Padding    [7]byte
}

type config struct {
	SaltSize   uint32
	KeySize    uint32
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
	NonceSize  int
	KeyVersion byte
}

type SecureBuffer struct {
	data   []byte
	mu     sync.Mutex
	zeroed atomic.Bool
}

func NewSecureBuffer(size int) *SecureBuffer {
	if size < 0 {
		size = 0
	}
	return &SecureBuffer{data: make([]byte, size)}
}

func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.data
}

func (sb *SecureBuffer) Zero() {
	if sb.zeroed.Load() {
		return
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.zeroed.Load() {
		return
	}
	for i := range sb.data {
		sb.data[i] = 0
	}
	sb.zeroed.Store(true)
	sink(sb.data)
}

func (sb *SecureBuffer) Close() error {
	sb.Zero()
	return nil
}

func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func validateSaltUniqueness(salt []byte) error {
	saltHex := hex.EncodeToString(salt)
	saltMu.RLock()
	_, exists := saltCache[saltHex]
	saltMu.RUnlock()
	if exists {
		return errors.New("salt reuse detected")
	}
	cp := make([]byte, len(salt))
	copy(cp, salt)
	saltMu.Lock()
	saltCache[saltHex] = cp
	saltMu.Unlock()
	saltWg.Add(1)
	go func(key string) {
		defer saltWg.Done()
		time.Sleep(time.Hour)
		saltMu.Lock()
		delete(saltCache, key)
		saltMu.Unlock()
	}(saltHex)
	return nil
}

func createFileIntegrity(header FileHeader, salt []byte) ([32]byte, error) {
	headerCopy := header
	headerCopy.Integrity = [32]byte{}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, headerCopy); err != nil {
		return [32]byte{}, err
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(buf.Bytes())
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func verifyFileIntegrity(header FileHeader, salt []byte) error {
	expected, err := createFileIntegrity(header, salt)
	if err != nil {
		return err
	}
	if !hmac.Equal(header.Integrity[:], expected[:]) {
		return errors.New("integrity mismatch")
	}
	return nil
}

func buildEnhancedAAD(header FileHeader, seq uint64) ([]byte, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, header.Magic)
	buf.WriteByte(header.Version)
	binary.Write(&buf, binary.LittleEndian, header.ArgonTime)
	binary.Write(&buf, binary.LittleEndian, header.ArgonMem)
	buf.WriteByte(header.ArgonUtil)
	binary.Write(&buf, binary.LittleEndian, header.KeySize)
	buf.WriteByte(header.KeyVersion)
	binary.Write(&buf, binary.LittleEndian, header.Timestamp)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	buf.Write(seqb[:])
	return buf.Bytes(), nil
}

func encryptChunk(outFile *os.File, plain []byte, aead cipher.AEAD, seq uint64, header FileHeader) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := csprng.Read(nonce); err != nil {
		return err
	}
	aad, err := buildEnhancedAAD(header, seq)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plain, aad)
	return writeChunk(outFile, nonce, ct)
}

func decryptChunk(inFile *os.File, aead cipher.AEAD, seq uint64, header FileHeader) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(inFile, nonce); err != nil {
		return nil, err
	}
	var clen uint32
	if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
		return nil, err
	}
	if clen > uint32(maxChunkSize) {
		return nil, errors.New("chunk too large")
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(inFile, ct); err != nil {
		return nil, err
	}
	aad, err := buildEnhancedAAD(header, seq)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	zeroBytes(ct)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return plain, nil
}

func processFile(ctx context.Context, inFile, outFile *os.File, key *SecureBuffer, cfg config, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return err
	}
	buf := NewSecureBuffer(cfg.ChunkSize)
	defer buf.Close()
	var seq uint64
	for {
		n, err := inFile.Read(buf.Bytes())
		if n > 0 {
			if err := encryptChunk(outFile, buf.Bytes()[:n], aead, seq, header); err != nil {
				return err
			}
			buf.Zero()
			seq++
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func decryptProcess(ctx context.Context, inFile, outFile *os.File, key *SecureBuffer, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return err
	}
	var seq uint64
	for {
		plain, err := decryptChunk(inFile, aead, seq, header)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := outFile.Write(plain); err != nil {
			return err
		}
		zeroBytes(plain)
		seq++
	}
}

func writeChunk(outFile *os.File, nonce, ct []byte) error {
	outFile.Write(nonce)
	binary.Write(outFile, binary.LittleEndian, uint32(len(ct)))
	outFile.Write(ct)
	return nil
}
