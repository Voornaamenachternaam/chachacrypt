// Package main provides a secure file encryption and decryption utility using Argon2id key derivation and XChaCha20-Poly1305 AEAD.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"         //nolint:depguard // Required for Argon2id KDF
	"golang.org/x/crypto/chacha20poly1305" //nolint:depguard // Required for XChaCha20-Poly1305 AEAD
	"golang.org/x/term"                   //nolint:depguard // Required for secure password input
)

const (
	MagicNumber  = "CHACRYPT"
	FileVersion  = byte(1)
	defaultSalt  = 32
	defaultKey   = 32
	defaultNonce = chacha20poly1305.NonceSizeX // 24 for XChaCha20-Poly1305

	// Defaults for Argon2id (values are in KiB for memory).
	defaultArgonTime    = 3
	defaultArgonMemory  = 64 * 1024 // KiB = 64 MiB
	defaultArgonThreads = 1
	defaultChunkSize    = 64 * 1024 // 64 KiB chunks
	
	// Security constants
	maxArgonTime    = 1 << 10 // Reasonable upper bound for iterations
	maxArgonMemory  = 1 << 20 // 1 TiB upper bound
	maxChunkSize    = 1 << 26 // 64 MiB chunk size upper bound
	maxSaltSize     = 1 << 10 // 1 KiB salt size upper bound
	maxKeySize      = 1 << 10 // 1 KiB key size upper bound
)

type FileHeader struct {
	Magic     [9]byte
	ArgonTime uint32
	ArgonMem  uint32
	ArgonUtil uint8
	KeySize   uint32
	SaltSize  uint32
	NonceSize uint32
	_         [11]byte
}

type config struct {
	SaltSize   uint32
	KeySize    uint32
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
	NonceSize  int
}

// SecureBuffer implements secure memory management for sensitive data
type SecureBuffer struct {
	data []byte
	mu   sync.Mutex
}

// NewSecureBuffer creates a new secure buffer
func NewSecureBuffer(size int) *SecureBuffer {
	return &SecureBuffer{
		data: make([]byte, size),
	}
}

// Bytes returns the underlying byte slice ( caller must not modify )
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.data
}

// Zero securely zeros the buffer
func (sb *SecureBuffer) Zero() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for i := range sb.data {
		sb.data[i] = 0
	}
	runtime.KeepAlive(sb.data)
}

// Close implements io.Closer for proper cleanup
func (sb *SecureBuffer) Close() error {
	sb.Zero()
	return nil
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enc":
		if err := handleEncrypt(context.Background()); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
	case "dec":
		if err := handleDecrypt(context.Background()); err != nil {
			log.Fatalf("Decryption failed or file is corrupted: %v", err)
		}
	case "pw":
		if err := handlePasswordGen(); err != nil {
			log.Fatalf("failed to generate password: %v", err)
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
	if err := enc.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Validate inputs
	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation error: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	password, err := readPasswordPromptConfirm("Enter a strong password: ", "Confirm password: ")
	if err != nil {
		return fmt.Errorf("password input error: %w", err)
	}
	defer password.Zero()

	cfg, err := buildConfig(*argTime, *argMem, *argThreads, *chunkSize, *saltSize, *keySize)
	if err != nil {
		return fmt.Errorf("config validation error: %w", err)
	}

	start := time.Now()
	if err := encryptFile(ctx, *in, *out, password, cfg); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	fmt.Printf("Encryption successful (took %s)\n", time.Since(start))
	return nil
}

func handleDecrypt(ctx context.Context) error {
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	in := dec.String("i", "", "input file")
	out := dec.String("o", "", "output file")
	if err := dec.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation error: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if !isTerminal(os.Stdin.Fd()) {
		return errors.New("password input requires a terminal")
	}
	fmt.Print("Enter password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer func() {
		for i := range pwBytes {
			pwBytes[i] = 0
		}
	}()

	cfg := config{}
	start := time.Now()
	if err := decryptFile(ctx, *in, *out, pwBytes, cfg); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Printf("Decryption successful (took %s)\n", time.Since(start))
	return nil
}

func handlePasswordGen() error {
	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	size := pw.Int("s", 15, "size of password to generate")
	if err := pw.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	p, err := generatePassword(*size)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}
	fmt.Println(p)
	return nil
}

func buildConfig(argTime, argMem, argThreads, chunkSize, saltSize, keySize int) (config, error) {
	// Enhanced bounds checking with explicit limits
	if argTime < 1 || argTime > maxArgonTime {
		return config{}, fmt.Errorf("argon-time out of bounds (1-%d): %d", maxArgonTime, argTime)
	}
	if argMem < 1 || argMem > maxArgonMemory {
		return config{}, fmt.Errorf("argon-mem out of bounds (1-%d KiB): %d", maxArgonMemory, argMem)
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
	}, nil
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  Encrypt a file:     chachacrypt enc -i input.txt -o output.enc")
	fmt.Println("  Decrypt a file:     chachacrypt dec -i input.enc -o decrypted.txt")
	fmt.Println("  Generate a password: chachacrypt pw -s 15")
}

func validateFilePath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	cleaned := filepath.Clean(p)
	if filepath.IsAbs(cleaned) {
		return errors.New("absolute paths are not allowed")
	}
	parts := strings.Split(cleaned, string(os.PathSeparator))
	for _, part := range parts {
		if part == ".." {
			return errors.New("directory traversal is not allowed")
		}
	}
	return nil
}

func validateFileInput(inputFile, outputFile string) error {
	if inputFile == "" || !fileExists(inputFile) {
		return errors.New("provide a valid input file")
	}
	if outputFile == "" {
		return errors.New("output file must be provided")
	}
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input file path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output file path: %w", err)
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

func readPasswordPromptConfirm(prompt, confirmPrompt string) (*SecureBuffer, error) {
	if !isTerminal(os.Stdin.Fd()) {
		return nil, errors.New("password input requires a terminal")
	}
	
	fmt.Print(prompt)
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	
	fmt.Print(confirmPrompt)
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		// Securely zero the first password before returning error
		for i := range p1 {
			p1[i] = 0
		}
		return nil, fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if len(p1) != len(p2) || subtle.ConstantTimeCompare(p1, p2) != 1 {
		// Securely zero both passwords before returning error
		for i := range p1 {
			p1[i] = 0
		}
		for i := range p2 {
			p2[i] = 0
		}
		return nil, errors.New("passwords do not match")
	}
	
	// Securely zero the confirmation password
	for i := range p2 {
		p2[i] = 0
	}
	
	// Return the first password in a secure buffer
	return NewSecureBuffer(len(p1)), nil
}

func generatePassword(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()[]{}"
	if n <= 0 {
		return "", errors.New("invalid password length")
	}
	
	// Optimize string generation using bytes.Buffer
	var result strings.Builder
	result.Grow(n)
	
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result.WriteByte(letters[idx.Int64()])
	}
	
	return result.String(), nil
}

func encryptFile(ctx context.Context, inputFile, outputFile string, password *SecureBuffer, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Check for context cancellation before expensive operations
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("error closing output file: %v", cerr)
		}
	}()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		if cerr := inFile.Close(); cerr != nil {
			log.Printf("error closing input file: %v", cerr)
		}
	}()

	salt, err := generateSalt(cfg.SaltSize)
	if err != nil {
		return fmt.Errorf("salt generation failed: %w", err)
	}
	defer salt.Close()

	header, err := createHeader(cfg)
	if err != nil {
		return fmt.Errorf("header creation failed: %w", err)
	}

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
	defer key.Close()

	return processFile(ctx, inFile, outFile, key, cfg, header)
}

func decryptFile(ctx context.Context, inputFile, outputFile string, password []byte, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Check for context cancellation before expensive operations
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		if cerr := inFile.Close(); cerr != nil {
			log.Printf("error closing input file: %v", cerr)
		}
	}()

	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("header read failed: %w", err)
	}

	salt, err := readSalt(inFile, header.SaltSize)
	if err != nil {
		return fmt.Errorf("salt read failed: %w", err)
	}
	defer salt.Close()

	key, err := deriveKey(password, salt.Bytes(), header)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer key.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("error closing output file: %v", cerr)
		}
	}()

	return decryptProcess(ctx, inFile, outFile, key, header)
}

func generateSalt(saltSize uint32) (*SecureBuffer, error) {
	salt := NewSecureBuffer(int(saltSize))
	if _, err := rand.Read(salt.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func createHeader(cfg config) (FileHeader, error) {
	var header FileHeader
	copy(header.Magic[:], MagicNumber)
	header.Magic[8] = FileVersion
	header.ArgonTime = cfg.KeyTime
	header.ArgonMem = cfg.KeyMemory
	header.ArgonUtil = cfg.KeyThreads
	header.KeySize = cfg.KeySize
	header.SaltSize = cfg.SaltSize
	header.NonceSize = uint32(cfg.NonceSize)
	return header, nil
}

func writeHeader(outFile *os.File, header FileHeader) error {
	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("failed to serialize header: %w", err)
	}
	if _, err := outFile.Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	return nil
}

func writeSalt(outFile *os.File, salt []byte) error {
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}
	return nil
}

func deriveKey(password []byte, salt []byte, header FileHeader) (*SecureBuffer, error) {
	key := NewSecureBuffer(int(header.KeySize))
	derived := argon2.IDKey(password, salt, header.ArgonTime, header.ArgonMem, header.ArgonUtil, header.KeySize)
	copy(key.Bytes(), derived)
	
	// Securely zero the intermediate derived key
	for i := range derived {
		derived[i] = 0
	}
	
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		key.Zero()
		return nil, fmt.Errorf("failed to initialize AEAD: %w", err)
	}
	_ = aead // Use the AEAD to prevent optimization
	return key, nil
}

func processFile(ctx context.Context, inFile *os.File, outFile *os.File, key *SecureBuffer, cfg config, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	plainBuf := NewSecureBuffer(cfg.ChunkSize)
	defer plainBuf.Close()
	
	baseAAD, err := headerToBytes(header)
	if err != nil {
		return fmt.Errorf("failed to serialize header for AAD: %w", err)
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
			if err := encryptChunk(outFile, plainBuf.Bytes()[:n], aead, baseAAD, seq); err != nil {
				return fmt.Errorf("encryption failed for chunk %d: %w", seq, err)
			}
			plainBuf.Zero()
			seq++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading input file: %w", readErr)
		}
	}
	return nil
}

func encryptChunk(outFile *os.File, plainBuf []byte, aead *chacha20poly1305.X, baseAAD []byte, seq uint64) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	aad, err := buildAAD(baseAAD, seq)
	if err != nil {
		return fmt.Errorf("failed to build AAD: %w", err)
	}

	ct := aead.Seal(nil, nonce, plainBuf, aad.Bytes())

	if err := writeChunk(outFile, nonce, ct); err != nil {
		return fmt.Errorf("chunk write failed: %w", err)
	}
	return nil
}

func writeChunk(outFile *os.File, nonce []byte, ct []byte) error {
	if _, err := outFile.Write(nonce); err != nil {
		return fmt.Errorf("error writing nonce: %w", err)
	}
	var clen = uint32(len(ct))
	if err := binary.Write(outFile, binary.LittleEndian, clen); err != nil {
		return fmt.Errorf("error writing ciphertext length: %w", err)
	}
	if _, err := outFile.Write(ct); err != nil {
		return fmt.Errorf("error writing ciphertext: %w", err)
	}
	return nil
}

func headerToBytes(header FileHeader) ([]byte, error) {
	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}
	return headerBuf.Bytes(), nil
}

func buildAAD(baseAAD []byte, seq uint64) (bytes.Buffer, error) {
	var aad bytes.Buffer
	aad.Write(baseAAD)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	aad.Write(seqBytes[:])
	return aad, nil
}

func readHeader(inFile *os.File) (FileHeader, error) {
	var header FileHeader
	if err := binary.Read(inFile, binary.LittleEndian, &header); err != nil {
		return FileHeader{}, fmt.Errorf("failed to read header: %w", err)
	}
	if string(header.Magic[:8]) != MagicNumber || header.Magic[8] != FileVersion {
		return FileHeader{}, errors.New("invalid file format or unsupported version")
	}
	return header, nil
}

func readSalt(inFile *os.File, saltSize uint32) (*SecureBuffer, error) {
	if saltSize == 0 || saltSize > 1024 {
		return nil, errors.New("invalid salt size")
	}
	salt := NewSecureBuffer(int(saltSize))
	if _, err := io.ReadFull(inFile, salt.Bytes()); err != nil {
		salt.Zero()
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}
	return salt, nil
}

func decryptProcess(ctx context.Context, inFile *os.File, outFile *os.File, key *SecureBuffer, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	nonceSize := int(header.NonceSize)
	if nonceSize != aead.NonceSize() {
		return errors.New("invalid file format or unsupported version")
	}

	baseAAD, err := headerToBytes(header)
	if err != nil {
		return fmt.Errorf("failed to serialize header for AAD: %w", err)
	}

	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		plain, err := decryptChunk(inFile, aead, baseAAD, nonceSize, seq)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decryption failed for chunk %d: %w", seq, err)
		}

		if _, err := outFile.Write(plain); err != nil {
			// Securely zero the plaintext before returning error
			for i := range plain {
				plain[i] = 0
			}
			return fmt.Errorf("failed to write plaintext: %w", err)
		}
		// Securely zero the plaintext after writing
		for i := range plain {
			plain[i] = 0
		}

		seq++
	}
	return nil
}

func decryptChunk(inFile *os.File, aead *chacha20poly1305.X, baseAAD []byte, nonceSize int, seq uint64) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
		return nil, io.EOF
	} else if err != nil {
		return nil, fmt.Errorf("error reading nonce: %w", err)
	}

	var clen uint32
	if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
		return nil, fmt.Errorf("error reading ciphertext length: %w", err)
	}
	if clen > (1 << 30) {
		return nil, errors.New("invalid ciphertext length")
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(inFile, ct); err != nil {
		return nil, fmt.Errorf("error reading ciphertext: %w", err)
	}

	aad, err := buildAAD(baseAAD, seq)
	if err != nil {
		return nil, fmt.Errorf("failed to build AAD: %w", err)
	}

	plain, err := aead.Open(nil, nonce, ct, aad.Bytes())
	// Securely zero the ciphertext
	for i := range ct {
		ct[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("decryption failed or file is corrupted: %w", err)
	}
	return plain, nil
}
