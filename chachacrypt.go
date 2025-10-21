package main

import (
	"crypto/rand"
	"encoding/binary"
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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	// File format header constants
	MagicNumber = "CHACRYPT"
	FileVersion = byte(1) // Current file format version

	// Argon2id and general crypto parameters
	defaultSaltSize  = 32
	defaultKeySize   = 32
	defaultKeyTime   = uint32(15) // Increased iterations for future-proofing (Proposal 1)
	defaultKeyMemory = uint32(1024 * 64)
	defaultChunkSize = 1024 * 32 // Original data chunk size

	// Max allowable file size for sanity checks.
	// 2GB should be more than enough for individual chunks length.
	maxFileChunkSize = uint32(2 * 1024 * 1024 * 1024)
)

// FileHeader defines the structure for the encrypted file header.
// This allows for future-proofing and parameter storage. (Proposal 2)
type FileHeader struct {
	Magic     [9]byte // "CHACRYPT\x01" (includes version)
	ArgonTime uint32
	ArgonMem  uint32
	ArgonUtil uint8    // Argon2id threads/parallelism
	KeySize   uint32   // Derived key size
	SaltSize  uint32   // Salt size for KDF
	NonceSize uint32   // Nonce size for AEAD
	_         [12]byte // Reserved for future expansion, pad to 48 bytes total
}

type Config struct {
	SaltSize   int
	KeySize    int
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
}

var config Config

func init() {
	threads := runtime.NumCPU()
	if threads > 255 {
		threads = 255
	}
	config = Config{
		SaltSize:   defaultSaltSize,
		KeySize:    defaultKeySize,
		KeyTime:    defaultKeyTime,
		KeyMemory:  defaultKeyMemory,
		KeyThreads: uint8(threads),
		ChunkSize:  defaultChunkSize,
	}
}

func main() {
	fmt.Println("Welcome to chachacrypt")

	enc := flag.NewFlagSet("enc", flag.ExitOnError)
	encInput := enc.String("i", "", "Input file to encrypt")
	encOutput := enc.String("o", "", "Output file")

	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	decInput := dec.String("i", "", "Input file to decrypt")
	decOutput := dec.String("o", "", "Output file")

	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	pwSizeFlag := pw.Int("s", 15, "Password length")

	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enc":
		_ = enc.Parse(os.Args[2:])
		if err := validateFileInput(*encInput, *encOutput); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		fmt.Print("Enter a strong password: ")
		password := readPassword() // returns []byte (Proposal 4)
		defer zeroBytes(password)  // Zero password from memory (Proposal 3)
		if err := encryptFile(*encInput, *encOutput, password); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Println("Encryption successful.")

	case "dec":
		_ = dec.Parse(os.Args[2:])
		if err := validateFileInput(*decInput, *decOutput); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		fmt.Print("Enter the password: ")
		password := readPassword() // returns []byte (Proposal 4)
		defer zeroBytes(password)  // Zero password from memory (Proposal 3)
		if err := decryptFile(*decInput, *decOutput, password); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("Decryption successful.")

	case "pw":
		_ = pw.Parse(os.Args[2:])
		password, err := generatePassword(*pwSizeFlag)
		if err != nil {
			log.Fatal(err)
		}
		if isTerminal(os.Stdout.Fd()) {
			fmt.Println("Generated Password:", password)
			fmt.Println("Please use it securely and avoid sharing or logging it.")
		} else {
			fmt.Println("WARNING: Generated password output not shown because stdout is not a terminal (potential log exposure).")
		}

	default:
		showHelp()
	}
}

func isTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  Encrypt a file:     chachacrypt enc -i input.txt -o output.enc")
	fmt.Println("  Decrypt a file:     chachacrypt dec -i input.enc -o decrypted-plaintext.txt") // Corrected to match README.md
	fmt.Println("  Generate a password:  chachacrypt pw -s 15")
}

// zeroBytes overwrites a byte slice with zeros to clear sensitive data from memory. (Proposal 3)
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func generatePassword(length int) (string, error) {
	if length < 12 {
		return "", errors.New("password length must be at least 12 characters")
	}

	characterSets := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"`~!@#$%^&*()_+-={}|[]\\;':\",./<>?",
	}

	var password strings.Builder
	rng := rand.Reader

	for i := 0; i < length; i++ {
		setIndex, err := rand.Int(rng, big.NewInt(int64(len(characterSets))))
		if err != nil {
			return "", fmt.Errorf("error generating password: %w", err)
		}
		charSet := characterSets[setIndex.Int64()]
		charIndex, err := rand.Int(rng, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", fmt.Errorf("error generating password: %w", err)
		}
		password.WriteByte(charSet[charIndex.Int64()])
	}

	return password.String(), nil
}

func validateFilePath(path string) error {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		return errors.New("absolute paths are not allowed")
	}
	if strings.Contains(cleaned, "..") {
		return errors.New("directory traversal is not allowed")
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

// encryptFile encrypts the inputFile to outputFile using the provided password. (Proposals 2, 3, 4, 6, 10)
func encryptFile(inputFile, outputFile string, password []byte) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Proposal 6: Check if output file exists and prompt user
	if fileExists(outputFile) {
		fmt.Printf("Output file '%s' already exists. Overwrite? (y/N): ", outputFile)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(strings.TrimSpace(response)) != "y" {
			return errors.New("operation cancelled by user")
		}
	}

	salt := make([]byte, config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	keyLen, err := safeUint32(config.KeySize) // Proposal 10
	if err != nil {
		return fmt.Errorf("invalid key size: %w", err)
	}
	key := argon2.IDKey(password, salt, config.KeyTime, config.KeyMemory, config.KeyThreads, keyLen)
	defer zeroBytes(key) // Zero key from memory (Proposal 3)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close resource: %v\n", err)
		}
	}()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close resource: %v\n", err)
		}
	}()

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating AEAD: %w", err)
	}
	nonceSize := aead.NonceSize()

	// Proposal 2: Write file header
	header := FileHeader{
		ArgonTime: config.KeyTime,
		ArgonMem:  config.KeyMemory,
		ArgonUtil: config.KeyThreads,
		KeySize:   uint32(config.KeySize),
		SaltSize:  uint32(config.SaltSize),
		NonceSize: uint32(nonceSize),
	}
	copy(header.Magic[:], MagicNumber)
	header.Magic[8] = FileVersion

	if err := binary.Write(outFile, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("error writing file header: %w", err)
	}

	// Write salt after header
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("error writing salt: %w", err)
	}

	buffer := make([]byte, config.ChunkSize)

	for {
		n, readErr := inFile.Read(buffer)
		if n > 0 {
			nonce := make([]byte, nonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("error generating nonce: %w", err)
			}

			ciphertext := aead.Seal(nil, nonce, buffer[:n], nil)
			if _, err := outFile.Write(nonce); err != nil {
				return fmt.Errorf("error writing nonce: %w", err)
			}

			length, err := safeUint32(len(ciphertext)) // Proposal 10
			if err != nil {
				return fmt.Errorf("ciphertext too large: %w", err)
			}
			if err := binary.Write(outFile, binary.LittleEndian, length); err != nil {
				return fmt.Errorf("error writing length: %w", err)
			}

			if _, err := outFile.Write(ciphertext); err != nil {
				return fmt.Errorf("error writing ciphertext: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading plaintext: %w", readErr)
		}
	}

	return nil
}

// decryptFile decrypts the inputFile to outputFile using the provided password. (Proposals 2, 3, 4, 6, 9, 10)
func decryptFile(inputFile, outputFile string, password []byte) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Proposal 6: Check if output file exists and prompt user
	if fileExists(outputFile) {
		fmt.Printf("Output file '%s' already exists. Overwrite? (y/N): ", outputFile)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(strings.TrimSpace(response)) != "y" {
			return errors.New("operation cancelled by user")
		}
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close resource: %v\n", err)
		}
	}()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close resource: %v\n", err)
		}
	}()

	// Proposal 2: Read and validate file header
	var header FileHeader
	if err := binary.Read(inFile, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("error reading file header: %w", err)
	}

	if string(header.Magic[:8]) != MagicNumber || header.Magic[8] != FileVersion {
		return fmt.Errorf("invalid file format or unsupported version. Expected magic '%s' version %d, got '%s' version %d", MagicNumber, FileVersion, string(header.Magic[:8]), header.Magic[8])
	}

	// Use parameters from header
	saltSize := int(header.SaltSize)
	keySize := int(header.KeySize)
	keyTime := header.ArgonTime
	keyMemory := header.ArgonMem
	keyThreads := header.ArgonUtil
	nonceSize := int(header.NonceSize)

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("error reading salt: %w", err)
	}

	keyLen, err := safeUint32(keySize) // Proposal 10
	if err != nil {
		return fmt.Errorf("invalid key size from header: %w", err)
	}
	key := argon2.IDKey(password, salt, keyTime, keyMemory, keyThreads, keyLen)
	defer zeroBytes(key) // Zero key from memory (Proposal 3)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating AEAD: %w", err)
	}

	if nonceSize != aead.NonceSize() {
		return fmt.Errorf("nonce size mismatch in header. Expected %d, got %d", aead.NonceSize(), nonceSize)
	}

	for {
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("error reading nonce: %w", err)
		}

		var length uint32
		if err := binary.Read(inFile, binary.LittleEndian, &length); err != nil {
			return fmt.Errorf("error reading ciphertext length: %w", err)
		}
		// Basic sanity check on length to prevent huge allocations / potential attacks
		if length == 0 || length > maxFileChunkSize {
			return fmt.Errorf("invalid ciphertext chunk length (%d), possibly corrupted or malicious file", length)
		}

		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(inFile, ciphertext); err != nil {
			return fmt.Errorf("error reading ciphertext: %w", err)
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			// Proposal 9: Improved error message for cryptographic failures
			return fmt.Errorf("decryption failed. This may indicate an incorrect password or a corrupted file: %w", err)
		}

		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("error writing plaintext: %w", err)
		}
	}

	return nil
}

// safeUint32 safely converts an int to uint32, returning an error if out of range. (Proposal 10)
func safeUint32(n int) (uint32, error) {
	if n < 0 || n > math.MaxUint32 { // Check for negative and exceeding max uint32
		return 0, fmt.Errorf("value %d out of uint32 range [%d, %d]", n, 0, math.MaxUint32)
	}
	return uint32(n), nil
}

// readPassword securely reads a password from stdin and returns it as a byte slice. (Proposal 4)
func readPassword() []byte {
	pwBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	// No TrimSpace here; password should be used as-is, including leading/trailing whitespace if user inputs it.
	return pwBytes
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
