package main

import (
	"crypto/rand"
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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	defaultSaltSize  = 32
	defaultKeySize   = 32
	defaultKeyTime   = uint32(5)
	defaultKeyMemory = uint32(1024 * 64)
	defaultChunkSize = 1024 * 32
)

// Config holds cryptographic parameters.
type Config struct {
	SaltSize   int
	KeySize    int
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
}

var config Config

// Initialize default cryptographic settings.
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
		fmt.Println("Enter a strong password:")
		password := readPassword()
		if err := encryptFile(*encInput, *encOutput, password); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Println("Encryption successful.")

	case "dec":
		_ = dec.Parse(os.Args[2:])
		if err := validateFileInput(*decInput, *decOutput); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		fmt.Println("Enter the password:")
		password := readPassword()
		if err := decryptFile(*decInput, *decOutput, password); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("Decryption successful.")

	case "pw":
		_ = pw.Parse(os.Args[2:])
		fmt.Println("Generated password:", generatePassword(*pwSizeFlag))

	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("Encrypt a file: chachacrypt enc -i input.txt -o output.enc")
	fmt.Println("Decrypt a file: chachacrypt dec -i input.enc -o output.txt")
	fmt.Println("Generate a password: chachacrypt pw -s 15")
}

func generatePassword(length int) string {
	if length < 12 {
		log.Fatal("Password length must be at least 12 characters.")
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
		setIndex, _ := rand.Int(rng, big.NewInt(int64(len(characterSets))))
		charSet := characterSets[setIndex.Int64()]
		charIndex, _ := rand.Int(rng, big.NewInt(int64(len(charSet))))
		password.WriteByte(charSet[charIndex.Int64()])
	}

	return password.String()
}

func validateFilePath(path string) error {
	// Clean the path to remove any relative components
	cleanedPath := filepath.Clean(path)
	
	// Check if the path attempts to traverse directories
	if filepath.IsAbs(cleanedPath) {
		return errors.New("absolute paths are not allowed")
	}
	
	// Check for directory traversal patterns
	if strings.Contains(cleanedPath, "..") {
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

func encryptFile(inputFile, outputFile, password string) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input file path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output file path: %w", err)
	}

	salt := make([]byte, config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	keySize, err := safeUint32(config.KeySize)
	if err != nil {
		return fmt.Errorf("invalid key size: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, keySize)

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	// Write salt
	if _, err := out.Write(salt); err != nil {
		return fmt.Errorf("error writing salt: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating AEAD: %w", err)
	}

	nonceSize := aead.NonceSize()
	chunk := make([]byte, config.ChunkSize)
	for {
		n, err := in.Read(chunk)
		if n > 0 {
			// Generate nonce
			nonce := make([]byte, nonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("error generating nonce: %w", err)
			}

			// Encrypt chunk
			encrypted := aead.Seal(nil, nonce, chunk[:n], nil)

			// Write nonce
			if _, err := out.Write(nonce); err != nil {
				return fmt.Errorf("error writing nonce: %w", err)
			}

			// Write encrypted data length
			encryptedLen, err := safeUint32(len(encrypted))
			if err != nil {
				return fmt.Errorf("encrypted data too large: %w", err)
			}
			
			if err := binary.Write(out, binary.LittleEndian, encryptedLen); err != nil {
				return fmt.Errorf("error writing encrypted length: %w", err)
			}

			// Write encrypted data
			if _, err := out.Write(encrypted); err != nil {
				return fmt.Errorf("error writing encrypted data: %w", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading input file: %w", err)
		}
	}

	return nil
}

func decryptFile(inputFile, outputFile, password string) error {
	if err := validateFilePath(inputFile); err != nil {
		return fmt.Errorf("invalid input file path: %w", err)
	}
	if err := validateFilePath(outputFile); err != nil {
		return fmt.Errorf("invalid output file path: %w", err)
	}

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	// Read salt
	salt := make([]byte, config.SaltSize)
	if _, err := in.Read(salt); err != nil {
		return fmt.Errorf("error reading salt: %w", err)
	}

	keySize, err := safeUint32(config.KeySize)
	if err != nil {
		return fmt.Errorf("invalid key size: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, keySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating AEAD: %w", err)
	}

	nonceSize := aead.NonceSize()
	for {
		// Read nonce
		nonce := make([]byte, nonceSize)
		_, err := io.ReadFull(in, nonce)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading nonce: %w", err)
		}

		// Read encrypted data length
		var encryptedLen uint32
		if err := binary.Read(in, binary.LittleEndian, &encryptedLen); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading encrypted length: %w", err)
		}

		// Read encrypted data
		encrypted := make([]byte, encryptedLen)
		if _, err := io.ReadFull(in, encrypted); err != nil {
			return fmt.Errorf("error reading encrypted data: %w", err)
		}

		// Decrypt
		plaintext, err := aead.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		// Write decrypted data
		if _, err := out.Write(plaintext); err != nil {
			return fmt.Errorf("error writing decrypted data: %w", err)
		}
	}

	return nil
}

func safeUint8(n int) (uint8, error) {
	if n < 0 || n > 255 {
		return 0, fmt.Errorf("value %d out of uint8 range", n)
	}
	return uint8(n), nil
}

func safeUint32(n int) (uint32, error) {
	if n < 0 {
		return 0, fmt.Errorf("value %d out of uint32 range", n)
	}
	return uint32(n), nil
}

func readPassword() string {
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return strings.TrimSpace(string(password))
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
