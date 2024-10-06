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
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"runtime"
)

const (
	defaultSaltSize   = 32
	defaultKeySize    = 32
	defaultKeyTime    = uint32(5)
	defaultKeyMemory  = uint32(1024 * 64)
	defaultKeyThreads = uint8(runtime.NumCPU())
	defaultChunkSize  = 1024 * 32
)

// Config holds the cryptographic parameters.
type Config struct {
	SaltSize   int
	KeySize    int
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	ChunkSize  int
}

var config Config

// init sets the default configuration.
func init() {
	config.SaltSize = defaultSaltSize
	config.KeySize = defaultKeySize
	config.KeyTime = defaultKeyTime
	config.KeyMemory = defaultKeyMemory
	config.KeyThreads = defaultKeyThreads
	config.ChunkSize = defaultChunkSize
}

// main function to parse commands and invoke appropriate actions.
func main() {
	fmt.Println("Welcome to chachacrypt")

	// Define command-line flags
	enc := flag.NewFlagSet("enc", flag.ExitOnError)
	encInput := enc.String("i", "", "Input file to encrypt")
	encOutput := enc.String("o", "", "Output filename")

	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	decInput := dec.String("i", "", "Input file to decrypt")
	decOutput := dec.String("o", "", "Output filename")

	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	pwSizeFlag := pw.Int("s", 15, "Password length")

	// Parse command-line arguments
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
		if err := encryption(*encInput, *encOutput); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

	case "dec":
		_ = dec.Parse(os.Args[2:])
		if err := validateFileInput(*decInput, *decOutput); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		if err := decryption(*decInput, *decOutput); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

	case "pw":
		_ = pw.Parse(os.Args[2:])
		fmt.Println("Generated Password:", getPassword(*pwSizeFlag))

	default:
		showHelp()
	}
}

// showHelp displays usage instructions.
func showHelp() {
	fmt.Println("Example commands:")
	fmt.Println("Encrypt a file: chachacrypt enc -i plaintext.txt -o ciphertext.enc")
	fmt.Println("Decrypt a file: chachacrypt dec -i ciphertext.enc -o decrypted-plaintext.txt")
	fmt.Println("Generate a password: chachacrypt pw -s 15")
}

// getPassword generates a random password of specified length.
func getPassword(pwLength int) string {
	if pwLength < 12 {
		log.Fatal("Error: Password length should be at least 12 characters.")
	}

	characterSets := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"`~!@#$%^&*()_+-={}|[]\\;':\",./<>?",
	}

	var password strings.Builder
	rng := rand.Reader
	for i := 0; i < pwLength; i++ {
		charSet := characterSets[i%len(characterSets)]
		charIndex, err := rand.Int(rng, big.NewInt(int64(len(charSet))))
		if err != nil {
			log.Fatal("Error generating password:", err)
		}
		password.WriteByte(charSet[charIndex.Int64()])
	}

	return password.String()
}

// validateFileInput checks if the input and output file names are valid.
func validateFileInput(inputFile, outputFile string) error {
	if inputFile == "" || !fileExists(inputFile) {
		return errors.New("provide a valid input file")
	}
	if outputFile == "" {
		return errors.New("output filename must be provided")
	}
	return nil
}

// encryption encrypts the input file and writes to the output file.
func encryption(plaintextFilename, ciphertextFilename string) error {
	fmt.Println("Encrypting.\nEnter a long and random password:")
	password := readPassword()

	salt := make([]byte, config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating random salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, config.KeySize)

	infile, err := os.Open(plaintextFilename)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer infile.Close()

	outfile, err := os.Create(ciphertextFilename)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer outfile.Close()

	if _, err := outfile.Write(salt); err != nil {
		return fmt.Errorf("error writing salt to output file: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	var wg sync.WaitGroup
	nonce := make([]byte, aead.NonceSize())
	buf := make([]byte, config.ChunkSize)

	for {
		n, err := infile.Read(buf)
		if n == 0 {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading from input file: %w", err)
		}

		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("error generating random nonce: %w", err)
		}

		wg.Add(1)
		go func(data []byte) {
			defer wg.Done()
			encrypted := aead.Seal(nil, nonce, data, nil)
			if _, err := outfile.Write(nonce); err != nil {
				log.Printf("error writing nonce to output file: %v", err)
			}
			if _, err := outfile.Write(encrypted); err != nil {
				log.Printf("error writing encrypted data to output file: %v", err)
			}
		}(buf[:n])
	}

	wg.Wait()
	zeroBytes(salt)
	zeroBytes(key)
	return nil
}

// decryption decrypts the input file and writes to the output file.
func decryption(ciphertextFilename, plaintextFilename string) error {
	fmt.Println("Decrypting.\nEnter the password:")
	password := readPassword()

	infile, err := os.Open(ciphertextFilename)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer infile.Close()

	outfile, err := os.Create(plaintextFilename)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer outfile.Close()

	salt := make([]byte, config.SaltSize)
	if _, err := infile.Read(salt); err != nil {
		return fmt.Errorf("error reading salt from input file: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, config.KeySize)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	buf := make([]byte, config.ChunkSize+aead.NonceSize())
	for {
		n, err := infile.Read(buf)
		if n == 0 {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading from input file: %w", err)
		}

		if n < aead.NonceSize() {
			return fmt.Errorf("not enough data to read nonce")
		}

		copy(nonce, buf[:aead.NonceSize()])
		ciphertext := buf[aead.NonceSize():n]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("error decrypting chunk: %w", err)
		}

		if _, err := outfile.Write(plaintext); err != nil {
			return fmt.Errorf("error writing decrypted data to output file: %w", err)
		}
	}

	zeroBytes(salt)
	zeroBytes(key)
	return nil
}

// readPassword securely reads the password from the terminal.
func readPassword() string {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatal("Error reading password from terminal:", err)
	}
	defer zeroBytes(password)
	return strings.TrimSpace(string(password))

// zeroBytes securely clears the byte slice
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// fileExists checks if the file exists.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}
