package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	nonceSize = chacha20poly1305.NonceSizeX
	keySize = chacha20poly1305.KeySize
	chunkSize = 64 * 1024
	versionByte = 1
)

func deriveKeyFromPassphrase(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase not allowed")
	}
	key := make([]byte, keySize)
	copy(key, passphrase)
	return key, nil
}

func encryptFile(inputPath, outputPath string, key []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	if _, err := outFile.Write([]byte{versionByte}); err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := inFile.Read(buf)
		if n > 0 {
			nonce := make([]byte, nonceSize)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}

			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)
			if _, err := outFile.Write(nonce); err != nil {
				return err
			}
			if _, err := outFile.Write(ciphertext); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	return nil
}

func decryptFile(inputPath, outputPath string, key []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	version := make([]byte, 1)
	if _, err := io.ReadFull(inFile, version); err != nil {
		return err
	}
	if version[0] != versionByte {
		return errors.New("unsupported file version")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	for {
		nonce := make([]byte, nonceSize)
		_, err := io.ReadFull(inFile, nonce)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		ciphertext := make([]byte, chunkSize+aead.Overhead())
		n, err := inFile.Read(ciphertext)
		if err != nil && err != io.EOF {
			return err
		}

		plaintext, decErr := aead.Open(nil, nonce, ciphertext[:n], nil)
		if decErr != nil {
			return decErr
		}

		if _, err := outFile.Write(plaintext); err != nil {
			return err
		}

		if n < len(ciphertext) {
			break
		}
	}

	return nil
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return password, err
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

	key, err := deriveKeyFromPassphrase(passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to derive key: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "encrypt":
		err = encryptFile(input, output, key)
	case "decrypt":
		err = decryptFile(input, output, key)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Operation failed: %v\n", err)
		os.Exit(1)
	}
}
