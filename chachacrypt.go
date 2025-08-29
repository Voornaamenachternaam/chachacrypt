package main

import (
    "crypto/rand"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/big"
    "os"
    "path/filepath"
    "runtime"
    "strings"

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
    threads := runtime.NumCPU()
    if threads > 255 {
        threads = 255
    }
    config = Config{
        SaltSize:   defaultSaltSize,
        KeySize:    defaultKeySize,
        KeyTime:    defaultKeyTime,
        KeyMemory:  defaultKeyMemory,
        KeyThreads: uint8(threads),
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
    pwSizeFlag := pw.Int("s", 15, "Password length")

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
        fmt.Print("Enter a strong password: ")
        password := readPassword()
        if err := encryptFile(*encInput, *encOutput, password); err != nil {
            log.Fatalf("Encryption failed: %v", err)
        }
        fmt.Println("Encryption successful.")

    case "dec":
        _ = dec.Parse(os.Args[2:])
        if err := validateFileInput(*decInput, *decOutput); err != nil {
            log.Fatalf("Input validation error: %v", err)
        }
        fmt.Print("Enter the password: ")
        password := readPassword()
        if err := decryptFile(*decInput, *decOutput, password); err != nil {
            log.Fatalf("Decryption failed: %v", err)
        }
        fmt.Println("Decryption successful.")

    case "pw":
        _ = pw.Parse(os.Args[2:])
        password, err := generatePassword(*pwSizeFlag)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("Generated password:", password)

    default:
        showHelp()
    }
}

func showHelp() {
    fmt.Println("Usage:")
    fmt.Println("  Encrypt a file:       chachacrypt enc -i input.txt -o output.enc")
    fmt.Println("  Decrypt a file:       chachacrypt dec -i input.enc -o output.txt")
    fmt.Println("  Generate a password:  chachacrypt pw -s 15")
}

func generatePassword(length int) (string, error) {
    if length < 12 {
        return "", errors.New("password length must be at least 12 characters")
    }

    characterSets := []string{
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?",
    }

    var password strings.Builder
    rng := rand.Reader

    for i := 0; i < length; i++ {
        setIndex, err := rand.Int(rng, big.NewInt(int64(len(characterSets))))
        if err != nil {
            return "", fmt.Errorf("error generating password: %w", err)
        }
        charSet := characterSets[setIndex.Int64()]
        charIndex, err := rand.Int(rng, big.NewInt(int64(len(charSet))))
        if err != nil {
            return "", fmt.Errorf("error generating password: %w", err)
        }
        password.WriteByte(charSet[charIndex.Int64()])
    }

    return password.String(), nil
}

func validateFilePath(path string) error {
    cleaned := filepath.Clean(path)
    if filepath.IsAbs(cleaned) {
        return errors.New("absolute paths are not allowed")
    }
    if strings.Contains(cleaned, "..") {
        return errors.New("directory traversal is not allowed")
    }
    return nil
}

func validateFileInput(inputFile, outputFile string) error {
    if inputFile == "" || !fileExists(inputFile) {
        return errors.New("provide a valid input file")
    }
    if outputFile == "" {
        return errors.New("output file must be provided")
    }
    if err := validateFilePath(inputFile); err != nil {
        return fmt.Errorf("invalid input file path: %w", err)
    }
    if err := validateFilePath(outputFile); err != nil {
        return fmt.Errorf("invalid output file path: %w", err)
    }
    return nil
}

func encryptFile(inputFile, outputFile, password string) error {
    if err := validateFilePath(inputFile); err != nil {
        return fmt.Errorf("invalid input path: %w", err)
    }
    if err := validateFilePath(outputFile); err != nil {
        return fmt.Errorf("invalid output path: %w", err)
    }

    salt := make([]byte, config.SaltSize)
    if _, err := rand.Read(salt); err != nil {
        return fmt.Errorf("error generating salt: %w", err)
    }

    keyLen, err := safeUint32(config.KeySize)
    if err != nil {
        return fmt.Errorf("invalid key size: %w", err)
    }
    key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, keyLen)

    inFile, err := os.Open(inputFile)
    if err != nil {
        return fmt.Errorf("error opening input file: %w", err)
    }
    defer inFile.Close()

    outFile, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("error creating output file: %w", err)
    }
    defer outFile.Close()

    if _, err := outFile.Write(salt); err != nil {
        return fmt.Errorf("error writing salt: %w", err)
    }

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return fmt.Errorf("error creating AEAD: %w", err)
    }

    nonceSize := aead.NonceSize()
    buffer := make([]byte, config.ChunkSize)

    for {
        n, readErr := inFile.Read(buffer)
        if n > 0 {
            nonce := make([]byte, nonceSize)
            if _, err := rand.Read(nonce); err != nil {
                return fmt.Errorf("error generating nonce: %w", err)
            }

            ciphertext := aead.Seal(nil, nonce, buffer[:n], nil)
            if _, err := outFile.Write(nonce); err != nil {
                return fmt.Errorf("error writing nonce: %w", err)
            }

            length, err := safeUint32(len(ciphertext))
            if err != nil {
                return fmt.Errorf("ciphertext too large: %w", err)
            }
            if err := binary.Write(outFile, binary.LittleEndian, length); err != nil {
                return fmt.Errorf("error writing length: %w", err)
            }

            if _, err := outFile.Write(ciphertext); err != nil {
                return fmt.Errorf("error writing ciphertext: %w", err)
            }
        }
        if readErr == io.EOF {
            break
        }
        if readErr != nil {
            return fmt.Errorf("error reading plaintext: %w", readErr)
        }
    }

    return nil
}

func decryptFile(inputFile, outputFile, password string) error {
    if err := validateFilePath(inputFile); err != nil {
        return fmt.Errorf("invalid input path: %w", err)
    }
    if err := validateFilePath(outputFile); err != nil {
        return fmt.Errorf("invalid output path: %w", err)
    }

    inFile, err := os.Open(inputFile)
    if err != nil {
        return fmt.Errorf("error opening input file: %w", err)
    }
    defer inFile.Close()

    outFile, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("error creating output file: %w", err)
    }
    defer outFile.Close()

    salt := make([]byte, config.SaltSize)
    if _, err := io.ReadFull(inFile, salt); err != nil {
        return fmt.Errorf("error reading salt: %w", err)
    }

    keyLen, err := safeUint32(config.KeySize)
    if err != nil {
        return fmt.Errorf("invalid key size: %w", err)
    }
    key := argon2.IDKey([]byte(password), salt, config.KeyTime, config.KeyMemory, config.KeyThreads, keyLen)

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return fmt.Errorf("error creating AEAD: %w", err)
    }

    nonceSize := aead.NonceSize()
    for {
        nonce := make([]byte, nonceSize)
        if _, err := io.ReadFull(inFile, nonce); err == io.EOF {
            break
        } else if err != nil {
            return fmt.Errorf("error reading nonce: %w", err)
        }

        var length uint32
        if err := binary.Read(inFile, binary.LittleEndian, &length); err != nil {
            return fmt.Errorf("error reading length: %w", err)
        }

        ciphertext := make([]byte, length)
        if _, err := io.ReadFull(inFile, ciphertext); err != nil {
            return fmt.Errorf("error reading ciphertext: %w", err)
        }

        plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
        if err != nil {
            return fmt.Errorf("decryption failed: %w", err)
        }

        if _, err := outFile.Write(plaintext); err != nil {
            return fmt.Errorf("error writing plaintext: %w", err)
        }
    }

    return nil
}

func safeUint32(n int) (uint32, error) {
    if n < 0 {
        return 0, fmt.Errorf("value %d out of uint32 range", n)
    }
    return uint32(n), nil
}

func readPassword() string {
    pwBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
    fmt.Println()
    return strings.TrimSpace(string(pwBytes))
}

func fileExists(name string) bool {
    _, err := os.Stat(name)
    return err == nil
}
