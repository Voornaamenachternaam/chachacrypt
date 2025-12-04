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
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

var (
	getPasswordError = errors.New("invalid password length")
	encryptionError  = errors.New("encryption error")
	decryptionError  = errors.New("decryption error")
	encryptionFAIL   = errors.New("Encryption FAIL")
)

const (
	SaltSize = 32
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: chachacrypt <command> [options]")
		fmt.Println("Commands: enc, dec, pw")
		os.Exit(1)
	}

	encCmd := flag.NewFlagSet("enc", flag.ExitOnError)
	encInput := encCmd.String("i", "", "Input file to encrypt")
	encOutput := encCmd.String("o", "", "Output file for encrypted data")

	decCmd := flag.NewFlagSet("dec", flag.ExitOnError)
	decInput := decCmd.String("i", "", "Input file to decrypt")
	decOutput := decCmd.String("o", "", "Output file for decrypted data")

	pwCmd := flag.NewFlagSet("pw", flag.ExitOnError)
	pwSize := pwCmd.Int("s", 15, "Generate password of given length")

	switch os.Args[1] {
	case "enc":
		if err := encCmd.Parse(os.Args[2:]); err != nil {
			log.Println("Error parsing enc args:", err)
			os.Exit(1)
		}
		if *encInput == "" {
			fmt.Println("Provide an input file to encrypt.")
			os.Exit(1)
		}
		out := *encOutput
		if out == "" {
			out = *encInput + ".enc"
		}
		if err := encryptFile(*encInput, out); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "dec":
		if err := decCmd.Parse(os.Args[2:]); err != nil {
			log.Println("Error parsing dec args:", err)
			os.Exit(1)
		}
		if *decInput == "" {
			fmt.Println("Provide an input file to decrypt.")
			os.Exit(1)
		}
		out := *decOutput
		if out == "" {
			in := *decInput
			out = "decrypted-" + in
			if len(in) > 4 && in[len(in)-4:] == ".enc" {
				out = "decrypted-" + in[:len(in)-4]
			}
		}
		if err := decryptFile(*decInput, out); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "pw":
		if err := pwCmd.Parse(os.Args[2:]); err != nil {
			log.Println("Error parsing pw args:", err)
			os.Exit(1)
		}
		pwd, err := getPassword(*pwSize)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Password:", pwd)
	default:
		fmt.Println("Unknown command:", os.Args[1])
		fmt.Println("Commands: enc, dec, pw")
		os.Exit(1)
	}
}

func getPassword(length int) (string, error) {
	if length <= 0 {
		return "", getPasswordError
	}
	const (
		smallAlpha   = "abcdefghijklmnopqrstuvwxyz"
		bigAlpha     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits       = "0123456789"
		specialChars = "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?"
	)
	letters := smallAlpha + bigAlpha + digits + specialChars
	pwd := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", getPasswordError
		}
		pwd[i] = letters[idx.Int64()]
	}
	return string(pwd), nil
}

func encryptFile(inputPath, outputPath string) error {
	fmt.Print("Encrypting.\nEnter a long and random password: ")
	bytepw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return encryptionError
	}
	fmt.Print("Enter the same password again: ")
	bytepw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return encryptionError
	}
	if !compareBytes(bytepw1, bytepw2) {
		return encryptionFAIL
	}
	salt := make([]byte, SaltSize)
	if n, err := rand.Read(salt); err != nil || n != SaltSize {
		return encryptionError
	}
	key := argon2.IDKey(bytepw1, salt, 15, 64*1024, uint8(minInt(runtime.NumCPU(), 255)), 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return encryptionError
	}
	inFile, err := os.Open(inputPath)
	if err != nil {
		return encryptionError
	}
	defer inFile.Close()
	outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return encryptionError
	}
	defer outFile.Close()
	if _, err := outFile.Write(salt); err != nil {
		return encryptionError
	}
	bufferSize := 32 * 1024
	buf := make([]byte, bufferSize)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			nonce := make([]byte, aead.NonceSize())
			if rn, err := rand.Read(nonce); err != nil || rn != len(nonce) {
				return encryptionError
			}
			ciphertext := aead.Seal(nonce, nonce, buf[:n], nil)
			if _, err := outFile.Write(ciphertext); err != nil {
				return encryptionError
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return encryptionError
		}
	}
	return nil
}

func decryptFile(inputPath, outputPath string) error {
	fmt.Print("Decrypting.\nEnter the password: ")
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return decryptionError
	}
	inFile, err := os.Open(inputPath)
	if err != nil {
		return decryptionError
	}
	defer inFile.Close()
	outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return decryptionError
	}
	defer outFile.Close()
	salt := make([]byte, SaltSize)
	n, err := io.ReadFull(inFile, salt)
	if err != nil || n != SaltSize {
		return decryptionError
	}
	key := argon2.IDKey(bytepw, salt, 15, 64*1024, uint8(minInt(runtime.NumCPU(), 255)), 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return decryptionError
	}
	bufferSize := 32*1024 + aead.NonceSize() + aead.Overhead()
	buf := make([]byte, bufferSize)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			if n < aead.NonceSize() {
				return decryptionError
			}
			nonce := buf[:aead.NonceSize()]
			ciphertext := buf[aead.NonceSize():n]
			plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return decryptionError
			}
			if _, err := outFile.Write(plaintext); err != nil {
				return decryptionError
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return decryptionError
		}
	}
	return nil
}

func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
