// chachacrypt.go
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	versionByte = 2 // bumped because file format now includes Argon2 salt header

	// XChaCha20-Poly1305 sizes
	nonceSize = chacha20poly1305.NonceSizeX
	keySize   = chacha20poly1305.KeySize

	// I/O chunking
	chunkSize = 64 * 1024 // 64 KiB

	// Argon2id parameters (balanced for interactive CLI use)
	// You can tune these later; raising timeCost or memoryKB increases security & CPU/RAM.
	argonTimeCost uint32 = 1         // iterations
	argonMemoryKB uint32 = 64 * 1024 // 64 MiB
	argonThreads  uint8  = 4         // parallelism
	saltSize             = 16        // bytes
)

// deriveKeyArgon2id derives a 32-byte key from passphrase and salt using Argon2id.
func deriveKeyArgon2id(passphrase, salt []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase not allowed")
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt length: %d", len(salt))
	}
	key := argon2.IDKey(passphrase, salt, argonTimeCost, argonMemoryKB, argonThreads, keySize)
	return key, nil
}

// encryptFile encrypts inputPath -> outputPath with per-file random salt and per-chunk random nonce.
// File format:
//
//	[1B version][1B saltLen][salt][ { per-chunk: [24B nonce][4B ctLenLE][ct] }... ]
func encryptFile(inputPath, outputPath string, passphrase []byte) (err error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := inFile.Close(); err == nil {
			err = cerr
		}
	}()

	// Create/truncate output atomically in place (no temp file to keep it simple)
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := outFile.Close(); err == nil {
			err = cerr
		}
	}()

	// Generate salt and derive key
	salt := make([]byte, saltSize)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key, err := deriveKeyArgon2id(passphrase, salt)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// Write header: version + saltLen + salt
	if _, err = outFile.Write([]byte{versionByte}); err != nil {
		return err
	}
	if _, err = outFile.Write([]byte{saltSize}); err != nil {
		return err
	}
	if _, err = outFile.Write(salt); err != nil {
		return err
	}

	// Encrypt in chunks, each with fresh random nonce; store ct length for robust reads.
	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, 4)
	for {
		n, rErr := inFile.Read(buf)
		if n > 0 {
			nonce := make([]byte, nonceSize)
			if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
				return fmt.Errorf("nonce: %w", err)
			}
			ct := aead.Seal(nil, nonce, buf[:n], nil)

			binary.LittleEndian.PutUint32(lenBuf, uint32(len(ct)))
			if _, err = outFile.Write(nonce); err != nil {
				return err
			}
			if _, err = outFile.Write(lenBuf); err != nil {
				return err
			}
			if _, err = outFile.Write(ct); err != nil {
				return err
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return rErr
		}
	}

	return nil
}

// decryptFile decrypts inputPath -> outputPath according to the format documented in encryptFile.
func decryptFile(inputPath, outputPath string, passphrase []byte) (err error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := inFile.Close(); err == nil {
			err = cerr
		}
	}()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := outFile.Close(); err == nil {
			err = cerr
		}
	}()

	// Read header
	var hdr [2]byte // version + saltLen
	if _, err = io.ReadFull(inFile, hdr[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if hdr[0] != versionByte {
		return fmt.Errorf("unsupported file version: %d", hdr[0])
	}
	sz := int(hdr[1])
	if sz != saltSize {
		return fmt.Errorf("unexpected salt length: %d", sz)
	}
	salt := make([]byte, sz)
	if _, err = io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("read salt: %w", err)
	}

	key, err := deriveKeyArgon2id(passphrase, salt)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// Stream chunks until EOF
	lenBuf := make([]byte, 4)
	for {
		nonce := make([]byte, nonceSize)
		_, err = io.ReadFull(inFile, nonce)
		if err == io.EOF {
			break // normal EOF between chunks means we're done
		}
		if err != nil {
			return fmt.Errorf("read nonce: %w", err)
		}

		if _, err = io.ReadFull(inFile, lenBuf); err != nil {
			return fmt.Errorf("read ct length: %w", err)
		}
		ctLen := binary.LittleEndian.Uint32(lenBuf)
		if ctLen == 0 {
			continue
		}
		ct := make([]byte, int(ctLen))
		if _, err = io.ReadFull(inFile, ct); err != nil {
			return fmt.Errorf("read ct: %w", err)
		}

		pt, decErr := aead.Open(nil, nonce, ct, nil)
		if decErr != nil {
			return fmt.Errorf("decrypt: %w", decErr)
		}
		if _, err = outFile.Write(pt); err != nil {
			return err
		}
	}

	return nil
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <encrypt|decrypt> <input> <output>\n", os.Args[0])
		os.Exit(1)
	}

	mode := os.Args[1]
	input := os.Args[2]
	output := os.Args[3]

	passphrase, err := readPassword("Enter passphrase: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read passphrase: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "encrypt":
		err = encryptFile(input, output, passphrase)
	case "decrypt":
		err = decryptFile(input, output, passphrase)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Operation failed: %v\n", err)
		os.Exit(1)
	}
}
