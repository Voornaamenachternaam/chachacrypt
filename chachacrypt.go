// chachacrypt.go

package main

import (
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
        fmt.Println("Password generated successfully.")
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
    fmt.Println("Encrypting...")
    password := getPasswordFromUser()

    salt := generateSalt()
    key := generateKey(password, salt)

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        log.Fatal("Error when creating cipher:", err)
    }

    inFile, err := os.Open(plaintextFilename)
    if err != nil {
        log.Fatal("Error when opening input file:", err)
    }
    defer inFile.Close()

    outFile, err := os.Create(ciphertextFilename)
    if err != nil {
        log.Fatal("Error when creating output file:", err)
    }
    defer outFile.Close()

    // Write salt to the beginning of the file
    _, err = outFile.Write(salt)
    if err != nil {
        log.Fatal("Error when writing salt to file:", err)
    }

    buf := make([]byte, chunkSize)
    for {
        n, err := inFile.Read(buf)
        if err != nil && err != io.EOF {
            log.Fatal("Error when reading input file chunk:", err)
        }
        if n == 0 {
            break
        }

        nonce := generateNonce(aead)

        ciphertext := aead.Seal(nil, nonce, buf[:n], nil)
        _, err = outFile.Write(ciphertext)
        if err != nil {
            log.Fatal("Error when writing ciphertext to file:", err)
        }
    }
    fmt.Println("Encryption completed successfully.")
}

func decryption(ciphertextFilename string, decryptedPlaintext string) {
    fmt.Println("Decrypting...")
    password := getPasswordFromUser()

    inFile, err := os.Open(ciphertextFilename)
    if err != nil {
        log.Fatal("Error when opening input file:", err)
    }
    defer inFile.Close()

    salt := make([]byte, SaltSize)
    _, err = inFile.Read(salt)
    if err != nil {
        log.Fatal("Error when reading salt from file:", err)
    }

    key := generateKey(password, salt)

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        log.Fatal("Error when creating cipher:", err)
    }

    outFile, err := os.Create(decryptedPlaintext)
    if err != nil {
        log.Fatal("Error when creating output file:", err)
    }
    defer outFile.Close()

    buf := make([]byte, chunkSize+aead.NonceSize())
    for {
        n, err := inFile.Read(buf)
        if err != nil && err != io.EOF {
            log.Fatal("Error encountered. Read", n, "bytes:", err)
        }
        if n == 0 {
            break
        }

        nonce := buf[:aead.NonceSize()]
        ciphertext := buf[aead.NonceSize():n]

        plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
        if err != nil {
            log.Fatal("Error when decrypting ciphertext. May be wrong password or file is damaged:", err)
        }

        _, err = outFile.Write(plaintext)
        if err != nil {
            log.Fatal("Error when writing decrypted data to file:", err)
        }
    }
    fmt.Println("Decryption completed successfully.")
}

func getPasswordFromUser() []byte {
    fmt.Println("Enter password:")
    password, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        log.Fatal("Error when reading password from terminal:", err)
    }
    return password
}

func generateSalt() []byte {
    salt := make([]byte, SaltSize)
    _, err := rand.Read(salt)
    if err != nil {
        log.Fatal("Error when generating salt:", err)
    }
    return salt
}

func generateKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, KeyTime, KeyMemory, KeyThreads, KeySize)
}

func generateNonce(aead *chacha20poly1305.Cipher) []byte {
    nonce := make([]byte, aead.NonceSize())
    _, err := rand.Read(nonce)
    if err != nil {
        log.Fatal("Error when generating nonce:", err)
    }
    return nonce
}
