package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"

	"crypto/subtle"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	SaltSize  = 32 // bytes
	NonceSize = chacha20poly1305.NonceSizeX
	KeySize   = chacha20poly1305.KeySize // 32 bytes
	chunkSize = 1024 * 32                // 32 KiB per chunk
)

var (
	defaultTime    uint32
	defaultMemory  uint32
	defaultThreads uint8
)

func init() {
	// Set Argon2id default parameters
	defaultTime = 15          // iterations
	defaultMemory = 64 * 1024 // memory in KiB (64 MiB)
	numCPU := runtime.NumCPU()
	if numCPU > 255 {
		numCPU = 255
	}
	defaultThreads = uint8(numCPU)
}

func main() {
	log.SetFlags(0) // no timestamp in logs
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	enc := flag.NewFlagSet("enc", flag.ExitOnError)
	enci := enc.String("i", "", "input file to encrypt")
	enco := enc.String("o", "", "output file")
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	deci := dec.String("i", "", "input file to decrypt")
	deco := dec.String("o", "", "output file")
	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	pwsize := pw.Int("s", 15, "password length")

	switch os.Args[1] {
	case "enc":
		enc.Parse(os.Args[2:])
		if *enci == "" {
			fmt.Fprintln(os.Stderr, "Error: input file (-i) is required for encryption.")
			os.Exit(1)
		}
		out := *enco
		if out == "" {
			out = *enci + ".enc"
		}
		encryptFile(*enci, out)
	case "dec":
		dec.Parse(os.Args[2:])
		if *deci == "" {
			fmt.Fprintln(os.Stderr, "Error: input file (-i) is required for decryption.")
			os.Exit(1)
		}
		out := *deco
		if out == "" {
			dd := *deci
			if strings.HasSuffix(dd, ".enc") {
				dd = dd[:len(dd)-4]
			}
			out = "decrypted-" + dd
		}
		decryptFile(*deci, out)
	case "pw":
		pw.Parse(os.Args[2:])
		fmt.Println("Generated password:", generatePassword(*pwsize))
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  enc -i <input> [-o <output>]    Encrypt a file")
	fmt.Println("  dec -i <input> [-o <output>]    Decrypt a file")
	fmt.Println("  pw  -s <length>               Generate a random password")
}

func generatePassword(length int) string {
	const (
		smallAlpha = "abcdefghijklmnopqrstuvwxyz"
		bigAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits     = "0123456789"
		special    = "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?"
	)
	charset := smallAlpha + bigAlpha + digits + special
	pwb := make([]byte, length)
	for i := range pwb {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			log.Println("Error generating password:", err)
			os.Exit(1)
		}
		pwb[i] = charset[num.Int64()]
	}
	return string(pwb)
}

func encryptFile(input, output string) {
	fmt.Print("Encrypting. Enter password: ")
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Println("Error reading password:", err)
		os.Exit(1)
	}
	fmt.Print("Re-enter password: ")
	bytepw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Println("Error reading password:", err)
		os.Exit(1)
	}
	// Constant-time compare for passwords
	if subtle.ConstantTimeCompare(bytepw, bytepw2) != 1 {
		fmt.Fprintln(os.Stderr, "Error: passwords do not match.")
		os.Exit(1)
	}

	// Generate random salt
	salt := make([]byte, SaltSize)
	if n, err := rand.Read(salt); err != nil || n != SaltSize {
		log.Println("Error generating salt:", err)
		os.Exit(1)
	}

	// Prompt before overwriting an existing file
	if _, err := os.Stat(output); err == nil {
		fmt.Printf("Output file '%s' exists. Overwrite? (y/N): ", output)
		var ans string
		fmt.Scanln(&ans)
		if strings.ToLower(ans) != "y" {
			fmt.Println("Encryption aborted.")
			os.Exit(0)
		}
	}

	outfile, err := os.Create(output)
	if err != nil {
		log.Println("Error creating output file:", err)
		os.Exit(1)
	}
	defer outfile.Close()

	// Write header: [time(1)][mem(4)][threads(1)][salt(32)][nonce_size(1)]
	header := make([]byte, 1+4+1+SaltSize+1)
	header[0] = byte(defaultTime)
	binary.BigEndian.PutUint32(header[1:5], defaultMemory)
	header[5] = byte(defaultThreads)
	copy(header[6:6+SaltSize], salt)
	header[6+SaltSize] = NonceSize
	if _, err := outfile.Write(header); err != nil {
		log.Println("Error writing header:", err)
		os.Exit(1)
	}

	// Derive key (32 bytes) using Argon2id
	key := argon2.IDKey(bytepw, salt, defaultTime, defaultMemory, defaultThreads, KeySize)
	// Clear password from memory
	for i := range bytepw {
		bytepw[i] = 0
	}
	for i := range bytepw2 {
		bytepw2[i] = 0
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Println("Error initializing cipher:", err)
		os.Exit(1)
	}

	infile, err := os.Open(input)
	if err != nil {
		log.Println("Error opening input file:", err)
		os.Exit(1)
	}
	defer infile.Close()

	buf := make([]byte, chunkSize)
	counter := uint64(0)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			// Generate random nonce
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+n+aead.Overhead())
			if m, err := rand.Read(nonce); err != nil || m != len(nonce) {
				log.Println("Error generating nonce:", err)
				os.Exit(1)
			}
			// Associated data: 8-byte chunk counter
			aad := make([]byte, 8)
			binary.BigEndian.PutUint64(aad, counter)
			ciphertext := aead.Seal(nonce, nonce, buf[:n], aad)
			if _, err := outfile.Write(ciphertext); err != nil {
				log.Println("Error writing ciphertext:", err)
				os.Exit(1)
			}
			counter++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println("Error reading input:", err)
			os.Exit(1)
		}
	}
}

func decryptFile(input, output string) {
	fmt.Print("Decrypting. Enter password: ")
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Println("Error reading password:", err)
		os.Exit(1)
	}

	infile, err := os.Open(input)
	if err != nil {
		log.Println("Error opening input file:", err)
		os.Exit(1)
	}
	defer infile.Close()

	// Read header
	header := make([]byte, 1+4+1+SaltSize+1)
	if n, err := infile.Read(header); err != nil {
		log.Println("Error reading header:", err)
		os.Exit(1)
	} else if n < len(header) {
		log.Println("Invalid file format.")
		os.Exit(1)
	}
	argonTime := uint32(header[0])
	argonMemory := binary.BigEndian.Uint32(header[1:5])
	argonThreads := uint8(header[5])
	salt := header[6 : 6+SaltSize]
	nonceSizeRead := header[6+SaltSize]
	if nonceSizeRead != NonceSize {
		log.Println("Unsupported nonce size:", nonceSizeRead)
		os.Exit(1)
	}

	// Derive key with extracted parameters
	key := argon2.IDKey(bytepw, salt, argonTime, argonMemory, argonThreads, KeySize)
	for i := range bytepw {
		bytepw[i] = 0
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Println("Error initializing cipher:", err)
		os.Exit(1)
	}

	if _, err := os.Stat(output); err == nil {
		fmt.Printf("Output file '%s' exists. Overwrite? (y/N): ", output)
		var ans string
		fmt.Scanln(&ans)
		if strings.ToLower(ans) != "y" {
			fmt.Println("Decryption aborted.")
			os.Exit(0)
		}
	}

	outfile, err := os.Create(output)
	if err != nil {
		log.Println("Error creating output file:", err)
		os.Exit(1)
	}
	defer outfile.Close()

	buf := make([]byte, aead.NonceSize()+chunkSize+aead.Overhead())
	counter := uint64(0)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			data := buf[:n]
			if len(data) < aead.NonceSize() {
				log.Println("Ciphertext too short.")
				os.Exit(1)
			}
			nonce := data[:aead.NonceSize()]
			ciphertext := data[aead.NonceSize():]
			aad := make([]byte, 8)
			binary.BigEndian.PutUint64(aad, counter)
			plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				log.Println("Decryption failed; wrong password or corrupted data.")
				os.Exit(1)
			}
			if _, err := outfile.Write(plaintext); err != nil {
				log.Println("Error writing plaintext:", err)
				os.Exit(1)
			}
			counter++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println("Error reading ciphertext:", err)
			os.Exit(1)
		}
	}
}
