// Drop-in replacement for chachacrypt.go
// Same as previous secure implementation but does NOT set restrictive OS-specific file permissions
// when creating output files, to ensure cross-platform compatibility.
//
// Features retained:
// - Password confirmation on encrypt
// - Argon2id KDF with configurable parameters
// - XChaCha20-Poly1305 AEAD with header bound as AAD and per-chunk sequence AAD
// - Per-chunk random nonces
// - Streaming chunked encrypt/decrypt
// - Explicit zeroing of sensitive buffers (best-effort)
// - Secure terminal password reading (TTY required)
// - Input/output path validation
// - Configurable parameters via flags
// - No OS-specific output file permission enforcement (uses os.Create)

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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
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
	SaltSize   int
	KeySize    int
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
		enc := flag.NewFlagSet("enc", flag.ExitOnError)
		in := enc.String("i", "", "input file (relative path, no .. allowed)")
		out := enc.String("o", "", "output file")
		argTime := enc.Int("argon-time", defaultArgonTime, "Argon2id time parameter (iterations)")
		argMem := enc.Int("argon-mem", defaultArgonMemory, "Argon2id memory parameter (KiB)")
		argThreads := enc.Int("argon-threads", defaultArgonThreads, "Argon2id parallelism (threads)")
		chunkSize := enc.Int("chunk-size", defaultChunkSize, "Chunk size in bytes for streaming encryption")
		saltSize := enc.Int("salt-size", defaultSalt, "Salt size in bytes")
		keySize := enc.Int("key-size", defaultKey, "Derived key size in bytes (e.g., 32)")
		_ = enc.Parse(os.Args[2:])

		if err := validateFileInput(*in, *out); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		if *in == *out {
			log.Fatalf("Input and output file must be different")
		}

		password, err := readPasswordPromptConfirm("Enter a strong password: ", "Confirm password: ")
		if err != nil {
			log.Fatalf("Password input error: %v", err)
		}
		defer zeroBytes(password)

		cfg := config{
			SaltSize:   *saltSize,
			KeySize:    *keySize,
			KeyTime:    uint32(*argTime),
			KeyMemory:  uint32(*argMem),
			KeyThreads: uint8(*argThreads),
			ChunkSize:  *chunkSize,
			NonceSize:  defaultNonce,
		}

		start := time.Now()
		if err := encryptFile(*in, *out, password, cfg); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Printf("Encryption successful (took %s)\n", time.Since(start))

	case "dec":
		dec := flag.NewFlagSet("dec", flag.ExitOnError)
		in := dec.String("i", "", "input file")
		out := dec.String("o", "", "output file")
		_ = dec.Parse(os.Args[2:])

		if err := validateFileInput(*in, *out); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		if *in == *out {
			log.Fatalf("Input and output file must be different")
		}

		if !isTerminal(os.Stdin.Fd()) {
			log.Fatalf("Password input requires a terminal")
		}
		fmt.Print("Enter password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("failed to read password: %v", err)
		}
		defer zeroBytes(pwBytes)

		cfg := config{}
		start := time.Now()
		if err := decryptFile(*in, *out, pwBytes, cfg); err != nil {
			log.Fatalf("Decryption failed or file is corrupted")
		}
		fmt.Printf("Decryption successful (took %s)\n", time.Since(start))

	case "pw":
		pw := flag.NewFlagSet("pw", flag.ExitOnError)
		size := pw.Int("s", 15, "size of password to generate")
		_ = pw.Parse(os.Args[2:])
		p, err := generatePassword(*size)
		if err != nil {
			log.Fatalf("failed to generate password: %v", err)
		}
		fmt.Println(p)

	default:
		showHelp()
		os.Exit(1)
	}
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

	// Use os.Create so default OS behavior is applied (cross-platform)
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		_ = outFile.Close()
	}()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		_ = inFile.Close()
	}()

	if cfg.SaltSize <= 0 {
		cfg.SaltSize = defaultSalt
	}
	if cfg.KeySize <= 0 {
		cfg.KeySize = defaultKey
	}
	if cfg.KeyTime == 0 {
		cfg.KeyTime = defaultArgonTime
	}
	if cfg.KeyMemory == 0 {
		cfg.KeyMemory = defaultArgonMemory
	}
	if cfg.KeyThreads == 0 {
		cfg.KeyThreads = uint8(defaultArgonThreads)
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	if cfg.NonceSize <= 0 {
		cfg.NonceSize = defaultNonce
	}

	salt := make([]byte, cfg.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	var header FileHeader
	copy(header.Magic[:], MagicNumber)
	header.Magic[8] = FileVersion
	header.ArgonTime = cfg.KeyTime
	header.ArgonMem = cfg.KeyMemory
	header.ArgonUtil = cfg.KeyThreads
	header.KeySize = uint32(cfg.KeySize)
	header.SaltSize = uint32(cfg.SaltSize)
	header.NonceSize = uint32(cfg.NonceSize)

	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("failed to serialize header: %w", err)
	}
	if _, err := outFile.Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	key := argon2.IDKey(password, salt, header.ArgonTime, header.ArgonMem, header.ArgonUtil, uint32(header.KeySize))
	aead, err := chacha20poly1305.NewX(key)
	zeroBytes(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	plainBuf := make([]byte, cfg.ChunkSize)
	baseAAD := headerBuf.Bytes()

	var seq uint64 = 0
	for {
		n, readErr := inFile.Read(plainBuf)
		if n > 0 {
			nonce := make([]byte, cfg.NonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("failed to generate nonce: %w", err)
			}

			var aad bytes.Buffer
			aad.Write(baseAAD)
			var seqBytes [8]byte
			binary.BigEndian.PutUint64(seqBytes[:], seq)
			aad.Write(seqBytes[:])

			ct := aead.Seal(nil, nonce, plainBuf[:n], aad.Bytes())

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

			zeroBytes(plainBuf[:n])
			zeroBytes(ct)

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
	defer inFile.Close()

	var header FileHeader
	if err := binary.Read(inFile, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	if string(header.Magic[:8]) != MagicNumber || header.Magic[8] != FileVersion {
		return errors.New("invalid file format or unsupported version")
	}

	saltSize := int(header.SaltSize)
	if saltSize <= 0 || saltSize > 1024 {
		return errors.New("invalid salt size")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	key := argon2.IDKey(password, salt, header.ArgonTime, header.ArgonMem, header.ArgonUtil, header.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	zeroBytes(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AEAD: %w", err)
	}

	// Use os.Create so default OS behavior is applied (cross-platform)
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		_ = outFile.Close()
	}()

	nonceSize := int(header.NonceSize)
	if nonceSize != aead.NonceSize() {
		return errors.New("invalid file format or unsupported version")
	}

	baseHeaderBuf := new(bytes.Buffer)
	if err := binary.Write(baseHeaderBuf, binary.LittleEndian, header); err != nil {
		return errors.New("internal error")
	}
	baseAAD := baseHeaderBuf.Bytes()

	var seq uint64 = 0
	for {
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
			break
		} else if err != nil {
			return errors.New("error reading nonce or reached unexpected EOF")
		}

		var clen uint32
		if err := binary.Read(inFile, binary.LittleEndian, &clen); err != nil {
			return errors.New("error reading ciphertext length")
		}
		if clen > (1 << 30) {
			return errors.New("invalid ciphertext length")
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(inFile, ct); err != nil {
			return errors.New("error reading ciphertext")
		}

		var aad bytes.Buffer
		aad.Write(baseAAD)
		var seqBytes [8]byte
		binary.BigEndian.PutUint64(seqBytes[:], seq)
		aad.Write(seqBytes[:])

		plain, err := aead.Open(nil, nonce, ct, aad.Bytes())
		zeroBytes(ct)
		if err != nil {
			return errors.New("decryption failed or file is corrupted")
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
