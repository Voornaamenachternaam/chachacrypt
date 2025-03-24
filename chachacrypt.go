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
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	defaultSaltSize   = 32
	defaultKeySize    = 32
	defaultKeyTime    = uint32(5)
	defaultKeyMemory  = uint32(1024 * 64)
	defaultChunkSize  = 1024 * 32
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
	config = Config{
		SaltSize:   defaultSaltSize,
		KeySize:    defaultKeySize,
		KeyTime:    defaultKeyTime,
		KeyMemory:  defaultKeyMemory,
		KeyThreads: uint8(runtime.NumCPU()), // Fixed issue with constant uint8 conversion
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
		if err := encryptFile(*encInput, *encOutput); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

	case "dec":
		_ = dec.Parse(os.Args[2:])
		if err := validateFileInput(*decInput, *decOutput); err != nil {
			log.Fatalf("Input validation error: %v", err)
		}
		if err := decryptFile(*decInput, *decOutput); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

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

func validateFileInput(inputFile, outputFile string) error {
	if inputFile == "" || !fileExists(inputFile) {
		return errors.New("provide a valid input file")
	}
	if outputFile == "" {
		return errors.New("output file must be provided")
	}
	return nil
}

func encryptFile(inputFile, outputFile string) error {
	fmt.Println("Enter a strong password:")
	password := readPassword()

	salt := make([]byte, config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, uint32(config.KeySize))

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

	if _, err := out.Write(salt); err != nil {
		return fmt.Errorf("error writing salt: %w", err)
	}

	aead, _ := chacha20poly1305.NewX(key)

	var wg sync.WaitGroup
	buf := make([]byte, config.ChunkSize)

	for {
		n, err := in.Read(buf)
		if n == 0 {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading input file: %w", err)
		}

		chunk := buf[:n]
		nonce := make([]byte, aead.NonceSize())
		rand.Read(nonce)

		wg.Add(1)
		go func() {
			defer wg.Done()
			encrypted := aead.Seal(nil, nonce, chunk, nil)
			out.Write(nonce)
			out.Write(encrypted)
		}()
	}

	wg.Wait()
	return nil
}

func decryptFile(inputFile, outputFile string) error {
	fmt.Println("Enter the password:")
	password := readPassword()

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

	salt := make([]byte, config.SaltSize)
	if _, err := in.Read(salt); err != nil {
		return fmt.Errorf("error reading salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, uint32(config.KeySize))
	aead, _ := chacha20poly1305.NewX(key)

	nonceSize := aead.NonceSize()
	buf := make([]byte, config.ChunkSize+nonceSize)

	for {
		n, err := in.Read(buf)
		if n == 0 && err == io.EOF {
			break
		}
		nonce := buf[:nonceSize]
		ciphertext := buf[nonceSize:n]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		out.Write(plaintext)
	}

	return nil
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
