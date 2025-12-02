package main

import (
	"bytes"
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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	// Default Argon2id parameters (time, memory in KiB, parallelism)
	DefaultArgonTime    = 3
	DefaultArgonMem     = 13
	DefaultArgonThreads = 1
	SaltSize            = 32        // salt length in bytes
	BaseKeySize         = 32        // key size in bytes (256-bit)
	ChunkSize           = 32 * 1024 // 32KB
	IntegritySize       = 32        // integrity array size
)

// FileHeader holds cryptographic parameters and sizes.
type FileHeader struct {
	KeySize   uint16
	SaltSize  uint16
	ChunkSize uint32
	NonceSize uint32
	reserved  uint32
	Integrity [IntegritySize]byte
}

// SecureBuffer holds sensitive data (like password).
type SecureBuffer struct {
	data []byte
}

// ReadPassword reads a password securely from stdin.
func ReadPassword(prompt string) (*SecureBuffer, error) {
	fmt.Print(prompt)
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return &SecureBuffer{data: pwd}, nil
}

// Wipe clears the secure buffer.
func (s *SecureBuffer) Wipe() {
	for i := range s.data {
		s.data[i] = 0
	}
}

// Bytes returns the underlying password bytes.
func (s *SecureBuffer) Bytes() []byte {
	return s.data
}

// zeroBytes overwrites a slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// buildEnhancedAAD constructs additional authenticated data from the header and chunk index.
func buildEnhancedAAD(h FileHeader, chunkIndex int) []byte {
	// Copy header and zero out Integrity
	hc := h
	for i := range hc.Integrity {
		hc.Integrity[i] = 0
	}
	var buf bytes.Buffer
	// Write header fields (LE)
	binary.Write(&buf, binary.LittleEndian, &hc) // writing to buffer should not fail
	// Append chunkIndex (uint64 LE)
	binary.Write(&buf, binary.LittleEndian, uint64(chunkIndex))
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	zeroBytes(buf.Bytes())
	return out
}

// deriveKey is a test helper: derive a key of length n using header fields (dummy deterministic).
func deriveKey(header FileHeader, n int) []byte {
	key := make([]byte, n)
	// Deterministic example: fill with sum of header values
	seed := uint32(header.KeySize) + uint32(header.SaltSize) + header.ChunkSize + header.NonceSize + header.reserved
	for i := range key {
		key[i] = byte((seed + uint32(i)) % 256)
	}
	return key
}

// writeAll writes all bytes in b to w.
func writeAll(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// writeSalt writes a length (uint16) and then the salt bytes.
func writeSalt(w io.Writer, salt []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint16(len(salt))); err != nil {
		return err
	}
	_, err := writeAll(w, salt)
	return err
}

// readSalt reads a uint16 length and then salt bytes.
func readSalt(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	salt := make([]byte, length)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// newAEADFromKey returns an XChaCha20-Poly1305 AEAD for the given key.
func newAEADFromKey(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key size for chacha20poly1305")
	}
	return chacha20poly1305.NewX(key)
}

// encryptFile encrypts input file to output using the provided password.
func encryptFile(inPath, outPath string, password *SecureBuffer) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Generate salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	// Derive key via Argon2id
	key := argon2.IDKey(password.Bytes(), salt, DefaultArgonTime, DefaultArgonMem, runtime.NumCPU(), uint32(BaseKeySize))
	aead, err := newAEADFromKey(key)
	if err != nil {
		return err
	}
	zeroBytes(key)

	// Prepare header
	header := FileHeader{
		KeySize:   uint16(BaseKeySize),
		SaltSize:  uint16(len(salt)),
		ChunkSize: uint32(ChunkSize),
		NonceSize: uint32(aead.NonceSize()),
	}
	// Write header (binary LE)
	if err := binary.Write(outFile, binary.LittleEndian, &header); err != nil {
		return err
	}
	// Write salt
	if err := writeSalt(outFile, salt); err != nil {
		return err
	}

	// Generate base nonce
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(baseNonce); err != nil {
		return err
	}
	// Write base nonce
	if _, err := writeAll(outFile, baseNonce); err != nil {
		return err
	}

	// Encrypt in chunks
	buf := make([]byte, ChunkSize)
	chunkIndex := 0
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		chunk := buf[:n]
		// Build nonce for this chunk: base plus chunkIndex
		nonce := make([]byte, aead.NonceSize())
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint64(nonce[aead.NonceSize()-8:], uint64(chunkIndex))
		// Build AAD
		aad := buildEnhancedAAD(header, chunkIndex)
		// Seal
		ciphertext := aead.Seal(nil, nonce, chunk, aad)
		if _, err := writeAll(outFile, ciphertext); err != nil {
			return err
		}
		chunkIndex++
	}
	return nil
}

// decryptFile decrypts input file to output using the provided password.
func decryptFile(inPath, outPath string, password *SecureBuffer) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Read header
	var header FileHeader
	if err := binary.Read(inFile, binary.LittleEndian, &header); err != nil {
		return err
	}
	// Read salt
	salt, err := readSalt(inFile)
	if err != nil {
		return err
	}
	// Read base nonce
	baseNonce := make([]byte, header.NonceSize)
	if _, err := io.ReadFull(inFile, baseNonce); err != nil {
		return err
	}

	// Derive key via Argon2id
	key := argon2.IDKey(password.Bytes(), salt, DefaultArgonTime, DefaultArgonMem, runtime.NumCPU(), uint32(header.KeySize))
	aead, err := newAEADFromKey(key)
	if err != nil {
		return err
	}
	zeroBytes(key)

	// Read all ciphertext
	cipherData, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	// Decrypt chunks
	offset := 0
	chunkIndex := 0
	tagSize := aead.Overhead()
	for offset < len(cipherData) {
		// Determine chunk length (may be last chunk shorter)
		expectedSize := int(header.ChunkSize) + tagSize
		if offset+expectedSize > len(cipherData) {
			expectedSize = len(cipherData) - offset
		}
		ciphertext := cipherData[offset : offset+expectedSize]
		// Build nonce for this chunk
		nonce := make([]byte, aead.NonceSize())
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint64(nonce[aead.NonceSize()-8:], uint64(chunkIndex))
		// Build AAD
		aad := buildEnhancedAAD(header, chunkIndex)
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return err
		}
		if _, err := writeAll(outFile, plaintext); err != nil {
			return err
		}
		offset += expectedSize
		chunkIndex++
	}
	return nil
}

// getPassword generates a random password of given length.
func getPassword(length int) (string, error) {
	const (
		smallAlpha   = "abcdefghijklmnopqrstuvwxyz"
		bigAlpha     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits       = "0123456789"
		specialChars = "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?"
	)
	chars := smallAlpha + bigAlpha + digits + specialChars
	var password strings.Builder
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		password.WriteByte(chars[idx.Int64()])
	}
	return password.String(), nil
}

// showHelp prints example usage.
func showHelp() {
	fmt.Println("Example usage:")
	fmt.Println("  Encrypt a file: chachacrypt enc -i plaintext.txt -o ciphertext.enc")
	fmt.Println("  Decrypt a file: chachacrypt dec -i ciphertext.enc -o decrypted.txt")
	fmt.Println("  Generate a password: chachacrypt pw -s 15")
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "enc":
		enc := flag.NewFlagSet("enc", flag.ExitOnError)
		inPath := enc.String("i", "", "input file to encrypt")
		outPath := enc.String("o", "", "output file")
		enc.Parse(os.Args[2:])
		if *inPath == "" {
			fmt.Println("Provide an input file to encrypt.")
			os.Exit(1)
		}
		if *outPath == "" {
			*outPath = *inPath + ".enc"
		}
		pwd, err := ReadPassword("Password: ")
		if err != nil {
			log.Fatal(err)
		}
		defer pwd.Wipe()
		if err := encryptFile(*inPath, *outPath, pwd); err != nil {
			log.Fatal(err)
		}

	case "dec":
		dec := flag.NewFlagSet("dec", flag.ExitOnError)
		inPath := dec.String("i", "", "input file to decrypt")
		outPath := dec.String("o", "", "output file")
		dec.Parse(os.Args[2:])
		if *inPath == "" {
			fmt.Println("Provide an input file to decrypt.")
			os.Exit(1)
		}
		if *outPath == "" {
			name := *inPath
			if strings.HasSuffix(name, ".enc") {
				*outPath = strings.TrimSuffix(name, ".enc")
			} else {
				*outPath = "decrypted-" + name
			}
		}
		pwd, err := ReadPassword("Password: ")
		if err != nil {
			log.Fatal(err)
		}
		defer pwd.Wipe()
		if err := decryptFile(*inPath, *outPath, pwd); err != nil {
			log.Fatal(err)
		}

	case "pw":
		pw := flag.NewFlagSet("pw", flag.ExitOnError)
		size := pw.Int("s", 15, "password length")
		pw.Parse(os.Args[2:])
		password, err := getPassword(*size)
		if err != nil {
			log.Fatal("Failed to generate password")
		}
		fmt.Println(password)

	default:
		showHelp()
		os.Exit(1)
	}
}
