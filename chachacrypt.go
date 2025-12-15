package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

const (
	magicString         = "CHACRYPT"
	currentVersion      = uint16(1)
	defaultSaltSize     = 24
	defaultNonceSize    = chacha20poly1305.NonceSizeX
	defaultChunkSize    = 64 * 1024
	defaultArgonTime    = uint32(3)
	defaultArgonMemory  = uint32(64 * 1024)
	defaultArgonThreads = uint8(1)
)

type FileHeader struct {
	Magic        [8]byte
	Version      uint16
	KeyVersion   uint16
	SaltSize     uint16
	NonceSize    uint16
	ChunkSize    uint32
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	_            [7]byte
	CreatedAt    int64
	Integrity    [32]byte
}

var (
	saltCache      = make(map[string]time.Time)
	saltCacheMutex sync.Mutex
	maxSaltCache   = 1024
)

type SecureKey struct {
	b []byte
}

func (s *SecureKey) Bytes() []byte { return s.b }

func (s *SecureKey) Destroy() {
	if s.b == nil {
		return
	}
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

func generateSalt(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid salt size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func safeCreateFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func validateSaltUniqueness(salt []byte) error {
	saltCacheMutex.Lock()
	defer saltCacheMutex.Unlock()

	if len(saltCache) >= maxSaltCache {
		for k := range saltCache {
			delete(saltCache, k)
			break
		}
	}
	key := hex.EncodeToString(salt)
	if _, exists := saltCache[key]; exists {
		return errors.New("salt reuse detected")
	}
	saltCache[key] = time.Now()
	return nil
}

func readPasswordPrompt() ([]byte, error) {
	fmt.Print("Enter password: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}
	return p, nil
}

func readNewPassword() ([]byte, error) {
	fmt.Print("Enter new password: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Print("\nConfirm new password: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p1, p2) {
		return nil, errors.New("passwords do not match")
	}
	return p1, nil
}

func deriveMasterKey(password, salt []byte, header FileHeader) (*SecureKey, error) {
	if password == nil || salt == nil {
		return nil, errors.New("password or salt nil")
	}
	iterations := header.ArgonTime
	if iterations == 0 {
		iterations = defaultArgonTime
	}
	memory := header.ArgonMemory
	if memory == 0 {
		memory = defaultArgonMemory
	}
	threads := header.ArgonThreads
	if threads == 0 {
		threads = defaultArgonThreads
	}
	key := argon2.IDKey(password, salt, iterations, memory, threads, 32)
	return &SecureKey{b: key}, nil
}

func deriveSubKeys(master []byte) (encKey, macKey []byte, err error) {
	if master == nil {
		return nil, nil, errors.New("master key nil")
	}
	// derive encKey
	hkdfEnc := hkdf.New(sha256.New, master, nil, []byte("chachacrypt-encryption"))
	encKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfEnc, encKey); err != nil {
		return nil, nil, err
	}
	// derive macKey
	hkdfMac := hkdf.New(sha256.New, master, nil, []byte("chachacrypt-header-mac"))
	macKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfMac, macKey); err != nil {
		zeroize(encKey)
		return nil, nil, err
	}
	return encKey, macKey, nil
}

func zeroize(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func computeHeaderMAC(header FileHeader, macKey []byte) ([32]byte, error) {
	var out [32]byte
	hdr := header
	var zero [32]byte
	hdr.Integrity = zero
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		return out, err
	}
	mac := hmac.New(sha256.New, macKey)
	if _, err := mac.Write(buf.Bytes()); err != nil {
		return out, err
	}
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func createFileIntegrity(header *FileHeader, macKey []byte) error {
	mac, err := computeHeaderMAC(*header, macKey)
	if err != nil {
		return err
	}
	header.Integrity = mac
	return nil
}

func verifyFileIntegrity(header FileHeader, macKey []byte) error {
	expected, err := computeHeaderMAC(header, macKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected[:], header.Integrity[:]) {
		return errors.New("header integrity verification failed")
	}
	return nil
}

func writeHeader(w io.Writer, header FileHeader) error {
	return binary.Write(w, binary.LittleEndian, header)
}

func readHeader(r io.Reader) (FileHeader, error) {
	var header FileHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return header, err
	}
	if string(bytes.Trim(header.Magic[:], "\x00")) != magicString {
		return header, errors.New("invalid magic")
	}
	if header.Version != currentVersion {
		return header, errors.New("unsupported version")
	}
	if header.SaltSize == 0 || header.NonceSize == 0 || header.ChunkSize == 0 {
		return header, errors.New("invalid header fields")
	}
	return header, nil
}

func encryptFile(inputPath, outputPath string, pass []byte) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := safeCreateFile(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	var header FileHeader
	copy(header.Magic[:], []byte(magicString))
	header.Version = currentVersion
	header.KeyVersion = 1
	header.SaltSize = uint16(defaultSaltSize)
	header.NonceSize = uint16(defaultNonceSize)
	header.ChunkSize = uint32(defaultChunkSize)
	header.ArgonTime = defaultArgonTime
	header.ArgonMemory = defaultArgonMemory
	header.ArgonThreads = defaultArgonThreads
	header.CreatedAt = time.Now().Unix()

	salt, err := generateSalt(int(header.SaltSize))
	if err != nil {
		return err
	}

	if err := validateSaltUniqueness(salt); err != nil {
		return err
	}

	master, err := deriveMasterKey(pass, salt, header)
	if err != nil {
		return err
	}
	defer master.Destroy()

	encKey, macKey, err := deriveSubKeys(master.Bytes())
	if err != nil {
		master.Destroy()
		return err
	}
	defer zeroize(encKey)
	defer zeroize(macKey)

	if err := createFileIntegrity(&header, macKey); err != nil {
		return err
	}

	if err := writeHeader(out, header); err != nil {
		return err
	}
	if _, err := out.Write(salt); err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	buf := make([]byte, header.ChunkSize)
	nonceBuf := make([]byte, header.NonceSize)
	for {
		n, er := in.Read(buf)
		if n > 0 {
			if _, err := io.ReadFull(rand.Reader, nonceBuf); err != nil {
				return err
			}
			ciphertext := aead.Seal(nil, nonceBuf, buf[:n], nil)
			if err := binary.Write(out, binary.LittleEndian, uint32(len(ciphertext))); err != nil {
				return err
			}
			if _, err := out.Write(nonceBuf); err != nil {
				return err
			}
			if _, err := out.Write(ciphertext); err != nil {
				return err
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			return er
		}
	}
	return nil
}

func decryptFile(inputPath, outputPath string, pass []byte) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	header, err := readHeader(in)
	if err != nil {
		return err
	}

	salt := make([]byte, header.SaltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return err
	}

	master, err := deriveMasterKey(pass, salt, header)
	if err != nil {
		return err
	}
	defer master.Destroy()

	encKey, macKey, err := deriveSubKeys(master.Bytes())
	if err != nil {
		return err
	}
	defer zeroize(encKey)
	defer zeroize(macKey)

	if err := verifyFileIntegrity(header, macKey); err != nil {
		return err
	}

	out, err := safeCreateFile(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	for {
		var clen uint32
		if err := binary.Read(in, binary.LittleEndian, &clen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if clen > uint32(header.ChunkSize)+chacha20poly1305.Overhead {
		    return errors.New("chunk size exceeds limit")
		}
		nonce := make([]byte, header.NonceSize)
		if _, err := io.ReadFull(in, nonce); err != nil {
			return err
		}
		ciphertext := make([]byte, clen)
		if _, err := io.ReadFull(in, ciphertext); err != nil {
			return err
		}
		plain, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return err
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
	}
	return nil
}

func readEncryptedFile(path string) (FileHeader, []byte, io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHeader{}, nil, nil, err
	}
	header, err := readHeader(f)
	if err != nil {
		_ = f.Close()
		return FileHeader{}, nil, nil, err
	}
	salt := make([]byte, header.SaltSize)
	if _, err := io.ReadFull(f, salt); err != nil {
		_ = f.Close()
		return FileHeader{}, nil, nil, err
	}
	return header, salt, f, nil
}

func reencryptFile(outputPath string, header FileHeader, newSalt []byte, chunksReader io.Reader, oldEncKey, oldMacKey, newEncKey, newMacKey []byte) error {
	out, err := safeCreateFile(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	header.SaltSize = uint16(len(newSalt))
	header.CreatedAt = time.Now().Unix()
	header.KeyVersion++

	if err := createFileIntegrity(&header, newMacKey); err != nil {
		return err
	}

	if err := writeHeader(out, header); err != nil {
		return err
	}
	if _, err := out.Write(newSalt); err != nil {
		return err
	}

	oldAead, err := chacha20poly1305.NewX(oldEncKey)
	if err != nil {
		return err
	}
	newAead, err := chacha20poly1305.NewX(newEncKey)
	if err != nil {
		return err
	}

	for {
		var clen uint32
		if err := binary.Read(chunksReader, binary.LittleEndian, &clen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		nonce := make([]byte, header.NonceSize)
		if _, err := io.ReadFull(chunksReader, nonce); err != nil {
			return err
		}
		ciphertext := make([]byte, clen)
		if _, err := io.ReadFull(chunksReader, ciphertext); err != nil {
			return err
		}
		plain, err := oldAead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return err
		}
		newNonce := make([]byte, header.NonceSize)
		if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
			return err
		}
		newCipher := newAead.Seal(nil, newNonce, plain, nil)
		if err := binary.Write(out, binary.LittleEndian, uint32(len(newCipher))); err != nil {
			return err
		}
		if _, err := out.Write(newNonce); err != nil {
			return err
		}
		if _, err := out.Write(newCipher); err != nil {
			return err
		}
	}
	return nil
}

func rotateKey(inputFile, outputFile string) error {
	oldPassword, err := readPasswordPrompt()
	if err != nil {
		return err
	}
	newPassword, err := readNewPassword()
	if err != nil {
		return err
	}

	header, salt, rdr, err := readEncryptedFile(inputFile)
	if err != nil {
		return err
	}
	defer rdr.Close()

	oldMaster, err := deriveMasterKey(oldPassword, salt, header)
	if err != nil {
		return err
	}
	defer oldMaster.Destroy()

	oldEncKey, oldMacKey, err := deriveSubKeys(oldMaster.Bytes())
	if err != nil {
		return err
	}
	defer zeroize(oldEncKey)
	defer zeroize(oldMacKey)

	newSalt, err := generateSalt(int(header.SaltSize))
	if err != nil {
		return err
	}

	newMaster, err := deriveMasterKey(newPassword, newSalt, header)
	if err != nil {
		return err
	}
	defer newMaster.Destroy()

	newEncKey, newMacKey, err := deriveSubKeys(newMaster.Bytes())
	if err != nil {
		return err
	}
	defer zeroize(newEncKey)
	defer zeroize(newMacKey)

	return reencryptFile(outputFile, header, newSalt, rdr, oldEncKey, oldMacKey, newEncKey, newMacKey)
}

func printUsage() {
	fmt.Println("Usage: chachacrypt -mode encrypt|decrypt|rotate -in <input> -out <output>")
	flag.PrintDefaults()
}

func main() {
	mode := flag.String("mode", "", "encrypt | decrypt | rotate")
	inPath := flag.String("in", "", "input file")
	outPath := flag.String("out", "", "output file")
	flag.Parse()

	if *mode == "" || *inPath == "" || *outPath == "" {
		printUsage()
		os.Exit(2)
	}

	switch strings.ToLower(*mode) {
	case "encrypt":
		pass, err := readPasswordPrompt()
		if err != nil {
			log.Fatalf("password: %v", err)
		}
		if err := encryptFile(*inPath, *outPath, pass); err != nil {
			log.Fatalf("encrypt failed: %v", err)
		}
	case "decrypt":
		pass, err := readPasswordPrompt()
		if err != nil {
			log.Fatalf("password: %v", err)
		}
		if err := decryptFile(*inPath, *outPath, pass); err != nil {
			log.Fatalf("decrypt failed: %v", err)
		}
	case "rotate":
		if err := rotateKey(*inPath, *outPath); err != nil {
			log.Fatalf("rotate failed: %v", err)
		}
	default:
		printUsage()
		os.Exit(2)
	}
}
