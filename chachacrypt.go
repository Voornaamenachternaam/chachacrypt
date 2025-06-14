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
	"runtime"
	"strings"
	"sync"

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
	// Cap threads to GOMAXPROCS to avoid oversubscription.
	maxProcs := runtime.GOMAXPROCS(0)
	numCPU := runtime.NumCPU()
	threads := uint8(numCPU)
	if numCPU > maxProcs {
		threads = uint8(maxProcs)
	}

	config = Config{
		SaltSize:   defaultSaltSize,
		KeySize:    defaultKeySize,
		KeyTime:    defaultKeyTime,
		KeyMemory:  defaultKeyMemory,
		KeyThreads: threads,
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
	pwSize := pw.Int("s", 15, "Password length (min 12)")

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
		fmt.Println("Generated password:", generatePassword(*pwSize))
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  Encrypt: chachacrypt enc -i input.txt -o output.enc")
	fmt.Println("  Decrypt: chachacrypt dec -i input.enc -o output.txt")
	fmt.Println("  Password: chachacrypt pw -s 15")
}

func generatePassword(length int) string {
	if length < 12 {
		log.Fatal("Password length must be at least 12 characters.")
	}

	sets := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"`~!@#$%^&*()_+-={}|[]\\;':\",./<>?",
	}

	var sb strings.Builder
	for i := 0; i < length; i++ {
		si, err := rand.Int(rand.Reader, big.NewInt(int64(len(sets))))
		if err != nil {
			log.Fatalf("Random error: %v", err)
		}
		set := sets[si.Int64()]

		ci, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			log.Fatalf("Random error: %v", err)
		}
		sb.WriteByte(set[ci.Int64()])
	}
	return sb.String()
}

func validateFileInput(inPath, outPath string) error {
	if inPath == "" || !fileExists(inPath) {
		return errors.New("provide a valid input file")
	}
	if outPath == "" {
		return errors.New("output file must be provided")
	}
	return nil
}

func encryptFile(inPath, outPath string) error {
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	password := string(passwordBytes)

	salt := make([]byte, config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, uint32(config.KeySize))
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initializing AEAD: %w", err)
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer outFile.Close()

	// Write salt and chunk size header
	if err := binary.Write(outFile, binary.BigEndian, uint32(config.SaltSize)); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("writing salt: %w", err)
	}
	if err := binary.Write(outFile, binary.BigEndian, uint32(config.ChunkSize)); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	sem := make(chan struct{}, config.KeyThreads)

	for {
		buf := make([]byte, config.ChunkSize)
		n, readErr := inFile.Read(buf)
		if n == 0 {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("reading input: %w", readErr)
		}

		plaintext := make([]byte, n)
		copy(plaintext, buf[:n])

		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generating nonce: %w", err)
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(pt, nn []byte) {
			defer wg.Done()
			defer func() { <-sem }()

			ciphertext := aead.Seal(nil, nn, pt, nil)
			packet := append(nn, ciphertext...)

			if _, err := outFile.Write(packet); err != nil {
				select {
				case errCh <- fmt.Errorf("writing chunk: %w", err):
				default:
				}
			}
		}(plaintext, nonce)

		// Check if any goroutine reported an error
		select {
		case e := <-errCh:
			return e
		default:
		}
	}

	wg.Wait()
	close(errCh)
	if e, ok := <-errCh; ok {
		return e
	}

	return nil
}

func decryptFile(inPath, outPath string) error {
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	password := string(passwordBytes)

	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer outFile.Close()

	// Read headers: salt size, salt, chunk size
	var saltSize uint32
	if err := binary.Read(inFile, binary.BigEndian, &saltSize); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("reading salt: %w", err)
	}
	var chunkSize uint32
	if err := binary.Read(inFile, binary.BigEndian, &chunkSize); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, uint32(config.KeySize))
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initializing AEAD: %w", err)
	}

	nonceSize := aead.NonceSize()
	packetSize := int(chunkSize) + nonceSize + aead.Overhead()
	buf := make([]byte, packetSize)

	for {
		n, readErr := inFile.Read(buf)
		if n == 0 {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("reading input: %w", readErr)
		}
		if n < nonceSize {
			return fmt.Errorf("malformed chunk: too small (%d bytes)", n)
		}

		nonce := buf[:nonceSize]
		ciphertext := buf[nonceSize:n]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}

	return nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
