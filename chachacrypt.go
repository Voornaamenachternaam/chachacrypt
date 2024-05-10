// chachacrypt.go

package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"io"
	"log"
	"os"
)

const (
	SaltSize   = 32 // in bytes
	NonceSize  = 24 // in bytes. taken from aead.NonceSize()
	KeySize    = uint32(32) // KeySize is 32 bytes (256 bits).
	KeyTime    = uint32(5)
	KeyMemory  = uint32(1024 * 64) // KeyMemory in KiB. here, 64 MiB.
	KeyThreads = uint8(4)
	chunkSize  = 1024 * 32 // chunkSize in bytes. here, 32 KiB.
)

func main() {
	fmt.Println("Welcome to chachacrypt")

	if len(os.Args) == 1 {
		showHelp()
		os.Exit(0)
	}

	enc := flag.NewFlagSet("enc", flag.ExitOnError)
	enci := enc.String("i", "", "Provide an input file to encrypt.")
	enco := enc.String("o", "", "Provide an output filename.")

	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	deci := dec.String("i", "", "Provide an input file to decrypt.")
	deco := dec.String("o", "", "Provide an output filename.")

	pw := flag.NewFlagSet("pw", flag.ExitOnError)
	pwsize := pw.Int("s", 15, "Generate password of given length.")

	switch os.Args[1] {
	case "enc":
		if err := enc.Parse(os.Args[2:]); err != nil {
			log.Fatal("Error when parsing arguments to enc:", err)
		}
		if *enci == "" {
			fmt.Println("Provide an input file to encrypt.")
			os.Exit(1)
		}
		if *enco != "" {
			encryption(*enci, *enco)
		} else {
			encryption(*enci, *enci+".enc")
		}

	case "dec":
		if err := dec.Parse(os.Args[2:]); err != nil {
			log.Fatal("Error when parsing arguments to dec:", err)
		}
		if *deci == "" {
			fmt.Println("Provide an input file to decrypt.")
			os.Exit(1)
		}
		if *deco != "" {
			decryption(*deci, *deco)
		} else {
			dd := *deci
			o := "decrypted-" + *deci
			if dd[len(dd)-4:] == ".enc" {
				o = "decrypted-" + dd[:len(dd)-4]
			}
			decryption(*deci, o)
		}

	case "pw":
		if err := pw.Parse(os.Args[2:]); err != nil {
			log.Fatal("Error when parsing arguments to pw:", err)
		}
		fmt.Println("Password:", getPassword(*pwsize))

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
	const (
		smallAlpha   = "abcdefghijklmnopqrstuvwxyz"
		bigAlpha     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits       = "0123456789"
		specialChars = "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?"
	)

	letters := smallAlpha + bigAlpha + digits + specialChars

	pw := make([]byte, pwLength)
	_, err := rand.Read(pw)
	if err != nil {
		log.Fatal("Error when generating password:", err)
	}

	for i := 0; i < pwLength; i++ {
		pw[i] = letters[int(pw[i])%len(letters)]
	}

	return string(pw)
}

func encryption(plaintextFilename string, ciphertextFilename string) {
	fmt.Println("Encrypting.\nEnter a long and random password:")
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Error when reading password from terminal:", err)
	}

	fmt.Println("\nEnter the same password again:")
	bytepw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Error when reading password from terminal:", err)
	}

	if !bytes.Equal(bytepw, bytepw2) {
		log.Fatal("Passwords don't match! Exiting.")
	}

	salt := make([]byte, SaltSize)
	_, err = rand.Read(salt)
	if err != nil {
		log.Fatal("Error when generating random salt:", err)
	}

	outfile, err := os.OpenFile(ciphertextFilename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("Error when opening/creating output file:", err)
	}
	defer outfile.Close()

	outfile.Write(salt)

	key := argon2.IDKey(bytepw, salt, KeyTime, KeyMemory, KeyThreads, KeySize)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal("Error when creating cipher:", err)
	}

	infile, err := os.Open(plaintextFilename)
	if err != nil {
		log.Fatal("Error when opening input file:", err)
	}
	defer infile.Close()

	buf := make([]byte, chunkSize)
	adCounter := 0 // associated data is a counter

	for {
		n, err := infile.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal("Error when reading input file chunk:", err)
		}

		if n > 0 {
			// Select a random nonce, and leave capacity for the ciphertext.
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+n+aead.Overhead())
			_, err := rand.Read(nonce)
			if err != nil {
				log.Fatal("Error when generating random nonce:", err)
			}

			msg := buf[:n]
			// Encrypt the message and append the ciphertext to the nonce.
			encryptedMsg := aead.Seal(nonce, nonce, msg, []byte(fmt.Sprintf("%d", adCounter)))
			outfile.Write(encryptedMsg)
			adCounter++
		}

		if err == io.EOF {
			break
		}
	}
}

func decryption(ciphertextFilename string, decryptedPlaintext string) {
	fmt.Println("Decrypting.\nEnter the password:")
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("Error when reading password from terminal:", err)
	}

	infile, err := os.Open(ciphertextFilename)
	if err != nil {
		log.Fatal("Error when opening input file:", err)
	}
	defer infile.Close()

	salt := make([]byte, SaltSize)
	n, err := infile.Read(salt)
	if n != SaltSize || err != nil {
		log.Fatal("Error: Salt should be", SaltSize, "bytes long:", err)
	}

	key := argon2.IDKey(bytepw, salt, KeyTime, KeyMemory, KeyThreads, KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal("Error when creating cipher:", err)
	}

	decBufSize := aead.NonceSize() + chunkSize + aead.Overhead()

	outfile, err := os.OpenFile(decryptedPlaintext, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("Error when opening output file:", err)
	}
	defer outfile.Close()

	buf := make([]byte, decBufSize)
	adCounter := 0 // associated data is a counter

	for {
		n, err := infile.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatalf("Error encountered. Read %d bytes: %v", n, err)
		}

		if n > 0 {
			encryptedMsg := buf[:n]
			if len(encryptedMsg) < aead.NonceSize() {
				log.Fatal("Error: Ciphertext is too short.")
			}

			// Split nonce and ciphertext.
			nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
			// Decrypt the message and check it wasn't tampered with.
			plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(fmt.Sprintf("%d", adCounter)))
			if err != nil {
				log.Fatal("Error when decrypting ciphertext. May be wrong password or file is damaged:", err)
			}

			outfile.Write(plaintext)
			adCounter++
		}

		if err == io.EOF {
			break
		}
	}
}
