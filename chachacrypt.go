// Package main provides a secure file encryption and decryption utility using Argon2id key derivation and XChaCha20-Poly1305 AEAD.
package main

import (
	"bytes"
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
	SaltSize   uint32 // Changed from int to uint32 to avoid overflow
	KeySize    uint32
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
	NonceSize  int
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enc":
		if err := handleEncrypt(); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
	case "dec":
		if err := handleDecrypt(); err != nil {
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

func handleEncrypt() error {
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
		return err
	}

	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation error: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
	}

	password, err := readPasswordPromptConfirm("Enter a strong password: ", "Confirm password: ")
	if err != nil {
		return fmt.Errorf("password input error: %w", err)
	}
	defer zeroBytes(password)

	cfg, err := buildConfig(*argTime, *argMem, *argThreads, *chunkSize, *saltSize, *keySize)
	if err != nil {
		return err
	}

	start := time.Now()
	if err := encryptFile(*in, *out, password, cfg); err != nil {
		return err
	}
	fmt.Printf("Encryption successful (took %s)\n", time.Since(start))
	return nil
}

func handleDecrypt() error {
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	in := dec.String("i", "", "input file")
	out := dec.String("o", "", "output file")
	if err := dec.Parse(os.Args[2:]); err != nil {
		return err
	}

	if err := validateFileInput(*in, *out); err != nil {
		return fmt.Errorf("input validation error: %w", err)
	}
	if *in == *out {
		return errors.New("input and output file must be different")
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
	defer zeroBytes(pwBytes)

	cfg := config{}
	start := time.Now()
	if err := decryptFile(*in, *out, pwBytes, cfg); err != nil {
		return err
	}
	fmt.Printf("Decryption successful (took %s)\n", time.Since(start))
	return nil
}

func handlePasswordGen() error {
	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	size := pw.Int("s", 15, "size of password to generate")
	if err := pw.Parse(os.Args[2:]); err != nil {
		return err
	}
	p, err := generatePassword(*size)
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func buildConfig(argTime, argMem, argThreads, chunkSize, saltSize, keySize int) (config, error) {
	// Check bounds to avoid overflow
	if argTime < 0 || argTime > 1<<30 {
		return config{}, errors.New("argon-time out of bounds")
	}
	if argMem < 0 || argMem > 1<<30 {
		return config{}, errors.New("argon-mem out of bounds")
	}
	if argThreads < 0 || argThreads > 1<<8 {
		return config{}, errors.New("argon-threads out of bounds")
	}
	if chunkSize < 0 || chunkSize > 1<<30 {
		return config{}, errors.New("chunk-size out of bounds")
	}
	if saltSize < 0 || saltSize > 1<<30 {
		return config{}, errors.New("salt-size out of bounds")
	}
	if keySize < 0 || keySize > 1<<30 {
		return config{}, errors.New("key-size out of bounds")
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

func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func readPasswordPromptConfirm(prompt, confirmPrompt string) ([]byte, error) {
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
		zeroBytes(p1)
		return nil, fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if len(p1) != len(p2) || subtle.ConstantTimeCompare(p1, p2) != 1 {
		zeroBytes(p1)
		zeroBytes(p2)
		return nil, errors.New("passwords do not match")
	}
	zeroBytes(p2)
	return p1, nil
}

func generatePassword(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()[]{}"
	if n <= 0 {
		return "", errors.New("invalid password length")
	}
	var b = make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[idx.Int64()]
	}
	return string(b), nil
}

func encryptFile(inputFile, outputFile string, password []byte, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return errors.New("invalid input path")
	}
	if err := validateFilePath(outputFile); err != nil {
		return errors.New("invalid output path")
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
		return err
	}

	header, err := createHeader(cfg)
	if err != nil {
		return err
	}

	if err := writeHeader(outFile, header); err != nil {
		return err
	}

	if err := writeSalt(outFile, salt); err != nil {
		return err
	}

	key, err := deriveKey(password, salt, header)
	if err != nil {
		return err
	}
	defer zeroBytes(key)

	return processFile(inFile, outFile, key, cfg, header)
}

func decryptFile(inputFile, outputFile string, password []byte, cfg config) error {
	if err := validateFilePath(inputFile); err != nil {
		return errors.New("invalid input path")
	}
	if err := validateFilePath(outputFile); err != nil {
		return errors.New("invalid output path")
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
		return err
	}

	salt, err := readSalt(inFile, header.SaltSize)
	if err != nil {
		return err
	}

	key, err := deriveKey(password, salt, header)
	if err != nil {
		return err
	}
	defer zeroBytes(key)

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			log.Printf("error closing output file: %v", cerr)
		}
	}()

	return decryptProcess(inFile, outFile, key, header)
}

func generateSalt(saltSize uint32) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
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

func deriveKey(password []byte, salt []byte, header FileHeader) ([]byte, error) {
	key := argon2.IDKey(password, salt, header.ArgonTime, header.ArgonMem, header.ArgonUtil, header.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("failed to initialize AEAD: %w", err)
	}
	// Return the key without zeroing for use in encryption; zeroed in defer
	_ = aead
	return key, nil
}

func processFile(inFile *os.File, outFile *os.File, key []byte, cfg config, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	plainBuf := make([]byte, cfg.ChunkSize)
	baseAAD, err := headerToBytes(header)
	if err != nil {
		return err
	}

	var seq uint64
	for {
		n, readErr := inFile.Read(plainBuf)
		if n > 0 {
			if err := encryptChunk(outFile, plainBuf[:n], aead, baseAAD, seq); err != nil {
				return err
			}
			zeroBytes(plainBuf[:n])
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
		return err
	}

	ct := aead.Seal(nil, nonce, plainBuf, aad.Bytes())

	if err := writeChunk(outFile, nonce, ct); err != nil {
		return err
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
	zeroBytes(ct)
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

func readSalt(inFile *os.File, saltSize uint32) ([]byte, error) {
	if saltSize == 0 || saltSize > 1024 {
		return nil, errors.New("invalid salt size")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}
	return salt, nil
}

func decryptProcess(inFile *os.File, outFile *os.File, key []byte, header FileHeader) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	nonceSize := int(header.NonceSize)
	if nonceSize != aead.NonceSize() {
		return errors.New("invalid file format or unsupported version")
	}

	baseAAD, err := headerToBytes(header)
	if err != nil {
		return err
	}

	var seq uint64
	for {
		plain, err := decryptChunk(inFile, aead, baseAAD, nonceSize, seq)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if _, err := outFile.Write(plain); err != nil {
			zeroBytes(plain)
			return errors.New("failed to write plaintext")
		}
		zeroBytes(plain)

		seq++
	}
	return nil
}

func decryptChunk(inFile *os.File, aead *chacha20poly1305.X, baseAAD []byte, nonceSize int, seq uint64) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
		return nil, io.EOF
	} else if err != nil {
		return nil, errors.New("error reading nonce or reached unexpected EOF")
	}

	var clen uint32
	if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
		return nil, errors.New("error reading ciphertext length")
	}
	if clen > (1 << 30) {
		return nil, errors.New("invalid ciphertext length")
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(inFile, ct); err != nil {
		return nil, errors.New("error reading ciphertext")
	}

	aad, err := buildAAD(baseAAD, seq)
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(nil, nonce, ct, aad.Bytes())
	zeroBytes(ct)
	if err != nil {
		return nil, errors.New("decryption failed or file is corrupted")
	}
	return plain, nil
}
