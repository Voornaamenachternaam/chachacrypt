// chachacrypt.go
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
		return nil // Not enough data for meaningful check
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
		return fmt.Errorf(
			"sample too small for required entropy: sample=%d, max_possible=%.6f, required=%.6f",
			len(sample), maxPossible, minEntropyBits,
		)
	}
	if entropy < minEntropyBits {
		return fmt.Errorf("insufficient entropy: %f < %f", entropy, minEntropyBits)
	}
	return nil
}

var (
	csprng    = &CSPRNGReader{}
	saltCache = make(map[string][]byte)
	saltMu    sync.RWMutex
	saltWg    sync.WaitGroup // For managing cleanup goroutine lifecycle
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
	return &SecureBuffer{
		data: make([]byte, size),
	}
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

func (sb *SecureBuffer) IsZeroed() bool {
	return sb.zeroed.Load()
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
		return errors.New("salt has been used before - potential security issue")
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
	var zeroIntegrity [32]byte
	headerCopy.Integrity = zeroIntegrity
	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, headerCopy); err != nil {
		return zeroIntegrity, fmt.Errorf("failed to serialize header: %w", err)
	}
	mac := hmac.New(sha256.New, salt)
	if _, err := mac.Write(headerBuf.Bytes()); err != nil {
		return zeroIntegrity, fmt.Errorf("hmac write failed: %w", err)
	}
	var integrity [32]byte
	copy(integrity[:], mac.Sum(nil))
	return integrity, nil
}

func verifyFileIntegrity(header FileHeader, salt []byte) error {
	expected, err := createFileIntegrity(header, salt)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}
	if !hmac.Equal(header.Integrity[:], expected[:]) {
		return errors.New("file metadata has been tampered with")
	}
	return nil
}

func buildEnhancedAAD(header FileHeader, chunkSeq uint64) ([]byte, error) {
	var aad bytes.Buffer
	if err := binary.Write(&aad, binary.LittleEndian, header.Magic); err != nil {
		return nil, err
	}
	if err := aad.WriteByte(header.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&aad, binary.LittleEndian, header.ArgonTime); err != nil {
		return nil, err
	}
	if err := binary.Write(&aad, binary.LittleEndian, header.ArgonMem); err != nil {
		return nil, err
	}
	if err := aad.WriteByte(header.ArgonUtil); err != nil {
		return nil, err
	}
	if err := binary.Write(&aad, binary.LittleEndian, header.KeySize); err != nil {
		return nil, err
	}
	if err := aad.WriteByte(header.KeyVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&aad, binary.LittleEndian, header.Timestamp); err != nil {
		return nil, err
	}
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], chunkSeq)
	if _, err := aad.Write(seqBytes[:]); err != nil {
		return nil, err
	}
	return aad.Bytes(), nil
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "enc":
		if err := handleEncrypt(context.Background()); err != nil {
			log.Fatalf("Processing failed: %v", err)
		}
	case "dec":
		if err := handleDecrypt(context.Background()); err != nil {
			log.Fatalf("Processing failed: %v", err)
		}
	case "pw":
		if err := handlePasswordGen(); err != nil {
			log.Fatalf("Password generation failed: %v", err)
		}
	case "rotate":
		if err := handleKeyRotation(context.Background()); err != nil {
			log.Fatalf("Key rotation failed: %v", err)
		}
	default:
		showHelp()
		os.Exit(1)
	}
}

func handleEncrypt(ctx context.Context) error {
	enc := flag.NewFlagSet("enc", flag.ExitOnError)
	in := enc.String("i", "", "input file (relative path, no .. allowed)")
	out := enc.String("o", "", "output file")
	argTime := enc.Int("argon-time", defaultArgonTime, "Argon2id time parameter (iterations)")
	argMem := enc.Int("argon-mem", defaultArgonMemory, "Argon2id memory parameter (KiB)")
	argThreads := enc.Int("argon-threads", defaultArgonThreads, "Argon2id parallelism (threads)")
	chunkSize := enc.Int("chunk-size", defaultChunkSize, "Chunk size in bytes for streaming encryption")
	saltSize := enc.Int("salt-size", defaultSalt, "Salt size in bytes")
	keySize := enc.Int("key-size", defaultKey, "Derived key size in bytes (e.g., 32)")
	keyVersion := enc.Uint("key-version", 0, "Key version for rotation support")
	if err := enc.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("flag parsing failed: %w", err)
	}
	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation failed: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	password, err := readPasswordPromptConfirm("Enter a strong password: ", "Confirm password: ")
	if err != nil {
		return fmt.Errorf("password input failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(password)
	cfg, err := buildConfig(*argTime, *argMem, *argThreads, *chunkSize, *saltSize, *keySize, byte(*keyVersion))
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	start := time.Now()
	if err := encryptFile(ctx, *in, *out, password, cfg); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	fmt.Printf("Processing successful (took %s)\n", time.Since(start))
	return nil
}

func handleDecrypt(ctx context.Context) error {
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	in := dec.String("i", "", "input file")
	out := dec.String("o", "", "output file")
	if err := dec.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("flag parsing failed: %w", err)
	}
	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation failed: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !isTerminal(os.Stdin.Fd()) {
		return errors.New("interactive input required")
	}
	fmt.Print("Enter password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("password read failed: %w", err)
	}
	defer zeroBytes(pwBytes)
	cfg := config{}
	start := time.Now()
	if err := decryptFile(ctx, *in, *out, pwBytes, cfg); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Printf("Processing successful (took %s)\n", time.Since(start))
	return nil
}

func handlePasswordGen() error {
	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	size := pw.Int("s", 15, "size of password to generate")
	if err := pw.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("flag parsing failed: %w", err)
	}
	p, err := generatePassword(*size)
	if err != nil {
		return fmt.Errorf("password generation failed: %w", err)
	}
	fmt.Println(p)
	return nil
}

func handleKeyRotation(ctx context.Context) error {
	rot := flag.NewFlagSet("rotate", flag.ExitOnError)
	in := rot.String("i", "", "input file to rotate key for")
	out := rot.String("o", "", "output file")
	newVersion := rot.Uint("new-version", 1, "new key version")
	if err := rot.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("flag parsing failed: %w", err)
	}
	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation failed: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !isTerminal(os.Stdin.Fd()) {
		return errors.New("interactive input required")
	}
	fmt.Print("Enter password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("password read failed: %w", err)
	}
	defer zeroBytes(pwBytes)
	if *newVersion > maxKeyVersion {
		return fmt.Errorf("key version too large (max %d): %d", maxKeyVersion, *newVersion)
	}
	return rotateKey(ctx, *in, *out, pwBytes, byte(*newVersion))
}

func buildConfig(argTime, argMem, argThreads, chunkSize, saltSize, keySize int, keyVersion byte) (config, error) {
	if argTime < 3 || argTime > maxArgonTime {
		return config{}, fmt.Errorf("argon-time out of bounds (3-%d): %d", maxArgonTime, argTime)
	}
	if argMem < 128*1024 || argMem > maxArgonMemory {
		return config{}, fmt.Errorf("argon-mem out of bounds (131072-%d KiB): %d", maxArgonMemory, argMem)
	}
	if argThreads < 1 || argThreads > runtime.NumCPU() {
		return config{}, fmt.Errorf("argon-threads out of bounds (1-%d): %d", runtime.NumCPU(), argThreads)
	}
	if chunkSize < 1024 || chunkSize > maxChunkSize {
		return config{}, fmt.Errorf("chunk-size out of bounds (1024-%d bytes): %d", maxChunkSize, chunkSize)
	}
	if saltSize < 16 || saltSize > maxSaltSize {
		return config{}, fmt.Errorf("salt-size out of bounds (16-%d bytes): %d", maxSaltSize, saltSize)
	}
	if keySize < 16 || keySize > maxKeySize {
		return config{}, fmt.Errorf("key-size out of bounds (16-%d bytes): %d", maxKeySize, keySize)
	}
	return config{
		SaltSize:   uint32(saltSize),
		KeySize:    uint32(keySize),
		KeyTime:    uint32(argTime),
		KeyMemory:  uint32(argMem),
		KeyThreads: uint8(argThreads),
		ChunkSize:  chunkSize,
		NonceSize:  defaultNonce,
		KeyVersion: keyVersion,
	}, nil
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println(" Encrypt a file: chachacrypt enc -i input.txt -o output.enc")
	fmt.Println(" Decrypt a file: chachacrypt dec -i input.enc -o decrypted.txt")
	fmt.Println(" Generate a password: chachacrypt pw -s 15")
	fmt.Println(" Rotate key: chachacrypt rotate -i input.enc -o output.enc -new-version 1")
}

func validateFilePath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	cleaned := filepath.Clean(p)
	if filepath.IsAbs(cleaned) {
		return errors.New("absolute paths not allowed")
	}
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, part := range parts {
		if part == ".." {
			return errors.New("directory traversal not allowed")
		}
	}
	return nil
}

func validateFileInput(inputFile, outputFile string) error {
	if inputFile == "" || !fileExists(inputFile) {
		return errors.New("valid input file required")
	}
	if outputFile == "" {
		return errors.New("output file required")
	}
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	return nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

func isTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	sink(b)
}

func readPasswordPromptConfirm(prompt, confirmPrompt string) (*SecureBuffer, error) {
	if !isTerminal(os.Stdin.Fd()) {
		return nil, errors.New("interactive input required")
	}
	fmt.Print(prompt)
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("password read failed: %w", err)
	}
	fmt.Print(confirmPrompt)
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		zeroBytes(p1)
		return nil, fmt.Errorf("password confirmation failed: %w", err)
	}
	if len(p1) != len(p2) || !ConstantTimeEqual(p1, p2) {
		zeroBytes(p1)
		zeroBytes(p2)
		return nil, errors.New("password mismatch")
	}
	sb := NewSecureBuffer(len(p1))
	copy(sb.Bytes(), p1)
	zeroBytes(p1)
	zeroBytes(p2)
	return sb, nil
}

func generatePassword(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()[]{}"
	if n <= 0 {
		return "", errors.New("invalid password length")
	}
	var result strings.Builder
	result.Grow(n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(csprng, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", fmt.Errorf("random generation failed: %w", err)
		}
		result.WriteByte(letters[idx.Int64()])
	}
	return result.String(), nil
}

func encryptFile(ctx context.Context, inputFile, outputFile string, password *SecureBuffer, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("file creation failed: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("file access failed: %w", err)
	}
	defer func() {
		if cerr := inFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	salt, err := generateSalt(cfg.SaltSize)
	if err != nil {
		return fmt.Errorf("salt generation failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(salt)
	header, err := createHeader(cfg)
	if err != nil {
		return fmt.Errorf("header creation failed: %w", err)
	}
	if err := validateSaltUniqueness(salt.Bytes()); err != nil {
		return fmt.Errorf("salt validation failed: %w", err)
	}
	integrity, err := createFileIntegrity(header, salt.Bytes())
	if err != nil {
		return fmt.Errorf("integrity creation failed: %w", err)
	}
	header.Integrity = integrity
	if err := writeHeader(outFile, header); err != nil {
		return fmt.Errorf("header write failed: %w", err)
	}
	if err := writeSalt(outFile, salt.Bytes()); err != nil {
		return fmt.Errorf("salt write failed: %w", err)
	}
	key, err := deriveKey(password.Bytes(), salt.Bytes(), header)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(key)
	return processFile(ctx, inFile, outFile, key, cfg, header)
}

func decryptFile(ctx context.Context, inputFile, outputFile string, password []byte, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("file access failed: %w", err)
	}
	defer func() {
		if cerr := inFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("file format error: %w", err)
	}
	salt, err := readSalt(inFile, header.SaltSize)
	if err != nil {
		return fmt.Errorf("salt read failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(salt)
	if err := verifyFileIntegrity(header, salt.Bytes()); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}
	key, err := deriveKey(password, salt.Bytes(), header)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(key)
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("file creation failed: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	return decryptProcess(ctx, inFile, outFile, key, header)
}

func rotateKey(ctx context.Context, inputFile, outputFile string, password []byte, newVersion byte) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("file access failed: %w", err)
	}
	defer func() {
		if cerr := inFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("file format error: %w", err)
	}
	salt, err := readSalt(inFile, header.SaltSize)
	if err != nil {
		return fmt.Errorf("salt read failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(salt)
	originalKey, err := deriveKey(password, salt.Bytes(), header)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(originalKey)
	header.KeyVersion = newVersion
	header.Timestamp = uint64(time.Now().Unix())
	integrity, err := createFileIntegrity(header, salt.Bytes())
	if err != nil {
		return fmt.Errorf("integrity creation failed: %w", err)
	}
	header.Integrity = integrity
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("file creation failed: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()
	if err := writeHeader(outFile, header); err != nil {
		return fmt.Errorf("header write failed: %w", err)
	}
	if err := writeSalt(outFile, salt.Bytes()); err != nil {
		return fmt.Errorf("salt write failed: %w", err)
	}
	if _, err := inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek failed: %w", err)
	}
	return processKeyRotation(ctx, inFile, outFile, originalKey, header)
}

func processKeyRotation(ctx context.Context, inFile, outFile *os.File, key *SecureBuffer, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return fmt.Errorf("AEAD initialization failed: %w", err)
	}
	baseAAD, err := buildEnhancedAAD(header, 0)
	if err != nil {
		return fmt.Errorf("AAD construction failed: %w", err)
	}
	headerSize := binary.Size(header)
	if headerSize <= 0 {
		return errors.New("invalid header size")
	}
	if _, err := inFile.Seek(int64(headerSize)+int64(header.SaltSize), io.SeekStart); err != nil {
		return fmt.Errorf("seek failed: %w", err)
	}
	nonceSize := int(header.NonceSize)
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("nonce read failed: %w", err)
		}
		var clen uint32
		if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
			return fmt.Errorf("length read failed: %w", err)
		}
		if clen > uint32(maxChunkSize) {
			return errors.New("chunk size exceeds limit")
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(inFile, ct); err != nil {
			return fmt.Errorf("ciphertext read failed: %w", err)
		}
		plain, err := aead.Open(nil, nonce, ct, baseAAD)
		zeroBytes(ct)
		if err != nil {
			return fmt.Errorf("decryption failed during rotation: %w", err)
		}
		newAAD, err := buildEnhancedAAD(header, seq)
		if err != nil {
			zeroBytes(plain)
			return fmt.Errorf("AAD reconstruction failed: %w", err)
		}
		newNonce := make([]byte, nonceSize)
		if _, err := csprng.Read(newNonce); err != nil {
			zeroBytes(plain)
			return fmt.Errorf("nonce generation failed: %w", err)
		}
		newCT := aead.Seal(nil, newNonce, plain, newAAD)
		zeroBytes(plain)
		if err := writeChunk(outFile, newNonce, newCT); err != nil {
			return fmt.Errorf("chunk write failed: %w", err)
		}
		seq++
	}
	return nil
}

func generateSalt(saltSize uint32) (*SecureBuffer, error) {
	if saltSize < 1 || saltSize > maxSaltSize {
		return nil, errors.New("invalid salt size")
	}
	salt := NewSecureBuffer(int(saltSize))
	if _, err := csprng.Read(salt.Bytes()); err != nil {
		salt.Zero()
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}
	return salt, nil
}

func createHeader(cfg config) (FileHeader, error) {
	var header FileHeader
	copy(header.Magic[:], MagicNumber)
	header.Version = FileVersion
	header.ArgonTime = cfg.KeyTime
	header.ArgonMem = cfg.KeyMemory
	header.ArgonUtil = cfg.KeyThreads
	header.KeySize = cfg.KeySize
	header.SaltSize = cfg.SaltSize
	header.NonceSize = uint32(cfg.NonceSize)
	header.KeyVersion = cfg.KeyVersion
	header.Timestamp = uint64(time.Now().Unix())
	for i := range header.Padding {
		if header.Padding[i] != 0 {
			return FileHeader{}, errors.New("non-zero padding detected")
		}
	}
	return header, nil
}

func writeHeader(outFile *os.File, header FileHeader) error {
	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("header serialization failed: %w", err)
	}
	if _, err := outFile.Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("header write failed: %w", err)
	}
	return nil
}

func writeSalt(outFile *os.File, salt []byte) error {
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("salt write failed: %w", err)
	}
	return nil
}

func deriveKey(password []byte, salt []byte, header FileHeader) (*SecureBuffer, error) {
	key := NewSecureBuffer(int(header.KeySize))
	derived := argon2.IDKey(password, salt, header.ArgonTime, header.ArgonMem, header.ArgonUtil, header.KeySize)
	copy(key.Bytes(), derived)
	for i := range derived {
		derived[i] = 0
	}
	if _, err := chacha20poly1305.NewX(key.Bytes()); err != nil {
		key.Zero()
		return nil, fmt.Errorf("AEAD initialization failed: %w", err)
	}
	return key, nil
}

func processFile(ctx context.Context, inFile *os.File, outFile *os.File, key *SecureBuffer, cfg config, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return fmt.Errorf("AEAD initialization failed: %w", err)
	}
	plainBuf := NewSecureBuffer(cfg.ChunkSize)
	defer func(sb *SecureBuffer) {
		if sb == nil {
			return
		}
		if cerr := sb.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}(plainBuf)
	baseAAD, err := buildEnhancedAAD(header, 0)
	if err != nil {
		return fmt.Errorf("AAD construction failed: %w", err)
	}
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, readErr := inFile.Read(plainBuf.Bytes())
		if n > 0 {
			if err := encryptChunk(outFile, plainBuf.Bytes()[:n], aead, baseAAD, seq, header); err != nil {
				return fmt.Errorf("encryption failed for chunk %d: %w", seq, err)
			}
			plainBuf.Zero()
			seq++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read failed: %w", readErr)
		}
	}
	return nil
}

func encryptChunk(outFile *os.File, plainBuf []byte, aead cipher.AEAD, baseAAD []byte, seq uint64, header FileHeader) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := csprng.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}
	aad, err := buildEnhancedAAD(header, seq)
	if err != nil {
		return fmt.Errorf("AAD construction failed: %w", err)
	}
	ct := aead.Seal(nil, nonce, plainBuf, aad)
	if err := writeChunk(outFile, nonce, ct); err != nil {
		return fmt.Errorf("chunk write failed: %w", err)
	}
	return nil
}

func writeChunk(outFile *os.File, nonce []byte, ct []byte) error {
	if _, err := outFile.Write(nonce); err != nil {
		return fmt.Errorf("nonce write failed: %w", err)
	}
	var clen = uint32(len(ct))
	if err := binary.Write(outFile, binary.LittleEndian, clen); err != nil {
		return fmt.Errorf("length write failed: %w", err)
	}
	if _, err := outFile.Write(ct); err != nil {
		return fmt.Errorf("ciphertext write failed: %w", err)
	}
	return nil
}

func readHeader(inFile *os.File) (FileHeader, error) {
	var header FileHeader
	if err := binary.Read(inFile, binary.LittleEndian, &header); err != nil {
		return FileHeader{}, fmt.Errorf("header read failed: %w", err)
	}
	if string(header.Magic[:]) != MagicNumber {
		return FileHeader{}, errors.New("invalid file format")
	}
	if header.Version > FileVersion {
		return FileHeader{}, fmt.Errorf("unsupported file version: %d", header.Version)
	}
	for i, b := range header.Padding {
		if b != 0 {
			return FileHeader{}, fmt.Errorf("non-zero padding at byte %d", i)
		}
	}
	return header, nil
}

func readSalt(inFile *os.File, saltSize uint32) (*SecureBuffer, error) {
	if saltSize < 16 || saltSize > maxSaltSize {
		return nil, errors.New("invalid salt size")
	}
	salt := NewSecureBuffer(int(saltSize))
	if _, err := io.ReadFull(inFile, salt.Bytes()); err != nil {
		salt.Zero()
		return nil, fmt.Errorf("salt read failed: %w", err)
	}
	return salt, nil
}

func decryptProcess(ctx context.Context, inFile *os.File, outFile *os.File, key *SecureBuffer, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return fmt.Errorf("AEAD initialization failed: %w", err)
	}
	nonceSize := int(header.NonceSize)
	if nonceSize != aead.NonceSize() {
		return errors.New("invalid file format")
	}
	baseAAD, err := buildEnhancedAAD(header, 0)
	if err != nil {
		return fmt.Errorf("AAD construction failed: %w", err)
	}
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		plain, err := decryptChunk(inFile, aead, baseAAD, seq, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("processing failed for chunk %d: %w", seq, err)
		}
		if _, err := outFile.Write(plain); err != nil {
			zeroBytes(plain)
			return fmt.Errorf("write failed: %w", err)
		}
		zeroBytes(plain)
		seq++
	}
	return nil
}

func decryptChunk(inFile *os.File, aead cipher.AEAD, baseAAD []byte, seq uint64, header FileHeader) ([]byte, error) {
	nonceSize := int(header.NonceSize)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
		return nil, io.EOF
	} else if err != nil {
		return nil, fmt.Errorf("nonce read failed: %w", err)
	}
	var clen uint32
	if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
		return nil, fmt.Errorf("length read failed: %w", err)
	}
	if clen > uint32(maxChunkSize) {
		return nil, errors.New("chunk size exceeds limit")
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(inFile, ct); err != nil {
		return nil, fmt.Errorf("ciphertext read failed: %w", err)
	}
	aad, err := buildEnhancedAAD(header, seq)
	if err != nil {
		zeroBytes(ct)
		return nil, fmt.Errorf("AAD construction failed: %w", err)
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	zeroBytes(ct)
	if err != nil {
		return nil, errors.New("processing failed - data corrupted or wrong key")
	}
	return plain, nil
}
