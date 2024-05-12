// chachacrypt.go

package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	SaltSize   = 32        // in bytes
	KeySize    = 32        // KeySize is 32 bytes (256 bits).
	KeyTime    = uint32(5)
	KeyMemory  = uint32(1024 * 64) // KeyMemory in KiB. here, 64 MiB.
	KeyThreads = uint8(4)
	ChunkSize  = 1024 * 32 // chunkSize in bytes. here, 32 KiB.
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
	pwSize := pw.Int("s", 15, "Password length")

	// Parse command-line arguments
	flag.Parse()
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enc":
		enc.Parse(os.Args[2:])
		if *encInput == "" {
			fmt.Println("Provide an input file to encrypt.")
			os.Exit(1)
		}
		if *encOutput == "" {
			*encOutput = *encInput + ".enc"
		}
		encryption(*encInput, *encOutput)

	case "dec":
		dec.Parse(os.Args[2:])
		if *decInput == "" {
			fmt.Println("Provide an input file to decrypt.")
			os.Exit(1)
		}
		if *decOutput == "" {
			*decOutput = strings.TrimSuffix(*decInput, ".enc")
		}
		decryption(*decInput, *decOutput)

	case "pw":
		pw.Parse(os.Args[2:])
		fmt.Println("Password:", getPassword(*pwSize))

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
	// Define character sets
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

func encryption(plaintextFilename, ciphertextFilename string) {
	// Prompt for password
	fmt.Println("Encrypting.\nEnter a long and random password:")
	password := readPassword()

	// Generate salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal("Error generating random salt:", err)
	}

	// Derive key from password and salt using Argon2
	key := argon2.IDKey([]byte(password), salt, KeyTime, KeyMemory, KeyThreads, KeySize)

	// Open input and output files
	infile, err := os.Open(plaintextFilename)
	if err != nil {
		log.Fatal("Error opening input file:", err)
	}
	defer infile.Close()

	outfile, err := os.Create(ciphertextFilename)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer outfile.Close()

	// Write salt to the beginning of the output file
	if _, err := outfile.Write(salt); err != nil {
		log.Fatal("Error writing salt to output file:", err)
	}

	// Create AEAD cipher with ChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	// Encrypt the file chunk by chunk
	buf := make([]byte, ChunkSize)
	nonce := make([]byte, aead.NonceSize())
	for {
		n, err := infile.Read(buf)
		if n == 0 && err == io.EOF {
			break
		} else if err != nil && err != io.EOF {
			log.Fatal("Error reading from input file:", err)
		}

		// Generate unique nonce for each chunk
		if _, err := rand.Read(nonce); err != nil {
			log.Fatal("Error generating random nonce:", err)
		}

		// Encrypt the chunk and write to output file
		encrypted := aead.Seal(nil, nonce, buf[:n], nil)
		if _, err := outfile.Write(encrypted); err != nil {
			log.Fatal("Error writing encrypted data to output file:", err)
		}
	}
}

func decryption(ciphertextFilename, plaintextFilename string) {
	// Prompt for password
	fmt.Println("Decrypting.\nEnter the password:")
	password := readPassword()

	// Open input and output files
	infile, err := os.Open(ciphertextFilename)
	if err != nil {
		log.Fatal("Error opening input file:", err)
	}
	defer infile.Close()

	outfile, err := os.Create(plaintextFilename)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer outfile.Close()

	// Read salt from the beginning of the input file
	salt := make([]byte, SaltSize)
	if _, err := infile.Read(salt); err != nil {
		log.Fatal("Error reading salt from input file:", err)
	}

	// Derive key from password and salt using Argon2
	key := argon2.IDKey([]byte(password), salt, KeyTime, KeyMemory, KeyThreads, KeySize)

	// Create AEAD cipher with ChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal("Error creating cipher:", err)
	}

	// Decrypt the file chunk by chunk
	buf := make([]byte, ChunkSize+aead.NonceSize())
	for {
		n, err := infile.Read(buf)
		if n == 0 && err == io.EOF {
			break
		} else if err != nil && err != io.EOF {
			log.Fatal("Error reading from input file:", err)
		}

		// Extract nonce and ciphertext from the chunk
		nonce := buf[:aead.NonceSize()]
		ciphertext := buf[aead.NonceSize():n]

		// Decrypt the chunk and write to output file
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Fatal("Error decrypting chunk:", err)
		}

		if _, err := outfile.Write(plaintext); err != nil {
			log.Fatal("Error writing decrypted data to output file:", err)
		}
	}
}

func readPassword() string {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Error reading password from terminal:", err)
	}
	return string(password)
}
