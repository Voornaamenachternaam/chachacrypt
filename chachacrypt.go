// chachacrypt.go

package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"runtime"
)

const (
	SaltSize   = 32        // Salt size in bytes.
	KeySize    = 32        // Key size is 32 bytes (256 bits).
	KeyTime    = uint32(5) // Argon2 time cost.
	KeyMemory  = uint32(1024 * 64) // Argon2 memory cost (64 MiB).
	KeyThreads = uint8(runtime.NumCPU())  // Use all available threads.
	ChunkSize  = 1024 * 32 // Chunk size in bytes (32 KiB).
)

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
		if *encInput == "" || !fileExists(*encInput) {
			fmt.Println("Error: Provide a valid input file to encrypt.")
			os.Exit(2)
		}
		if *encOutput == "" {
			*encOutput = *encInput + ".enc"
		}
		if err := encryption(*encInput, *encOutput); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

	case "dec":
		_ = dec.Parse(os.Args[2:])
		if *decInput == "" || !fileExists(*decInput) {
			fmt.Println("Error: Provide a valid input file to decrypt.")
			os.Exit(2)
		}
		if *decOutput == "" {
			*decOutput = strings.TrimSuffix(*decInput, ".enc")
		}
		if err := decryption(*decInput, *decOutput); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

	case "pw":
		_ = pw.Parse(os.Args[2:])
		fmt.Println("Password:", getPassword(*pwSizeFlag))

	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Example commands:")
	fmt.Println("Encrypt a file: chachacrypt enc -i plaintext.txt -o ciphertext.enc")
	fmt.Println("Decrypt a file: chachacrypt dec -i ciphertext.enc -o decrypted-plaintext.txt")
	fmt.Println("Generate a password: chachacrypt pw -s 15")
}

func getPassword(pwLength int) string {
	if pwLength < 12 {
		log.Fatal("Error: Password length should be at least 12 characters.")
	}

	// Character sets
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

func encryption(plaintextFilename, ciphertextFilename string) error {
	fmt.Println("Encrypting.\nEnter a long and random password:")
	password := readPassword()

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating random salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, KeyTime, KeyMemory, KeyThreads, KeySize)

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

	buf := make([]byte, ChunkSize)
	nonce := make([]byte, aead.NonceSize())
	for {
		n, err := infile.Read(buf)
		if n == 0 && err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("error reading from input file: %w", err)
		}

		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("error generating random nonce: %w", err)
		}

		encrypted := aead.Seal(nil, nonce, buf[:n], nil)
		if _, err := outfile.Write(nonce); err != nil {
			return fmt.Errorf("error writing nonce to output file: %w", err)
		}
		if _, err := outfile.Write(encrypted); err != nil {
			return fmt.Errorf("error writing encrypted data to output file: %w", err)
		}
	}

	// Zero sensitive data
	zeroBytes(salt)
	zeroBytes(key)
	return nil
}

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

	salt := make([]byte, SaltSize)
	if _, err := infile.Read(salt); err != nil {
		return fmt.Errorf("error reading salt from input file: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, KeyTime, KeyMemory, KeyThreads, KeySize)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	buf := make([]byte, ChunkSize+aead.NonceSize())
	for {
		n, err := infile.Read(buf)
		if n == 0 && err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("error reading from input file: %w", err)
		}

		nonce := buf[:aead.NonceSize()]
		ciphertext := buf[aead.NonceSize():n]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("error decrypting chunk: %w", err)
		}

		if _, err := outfile.Write(plaintext); err != nil {
			return fmt.Errorf("error writing decrypted data to output file: %w", err)
		}
	}

	// Zero sensitive data
	zeroBytes(salt)
	zeroBytes(key)
	return nil
}

func readPassword() string {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatal("Error reading password from terminal:", err)
	}
	defer zeroBytes(password)
	return strings.TrimSpace(string(password))
}

// zeroBytes securely clears the byte slice
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}
