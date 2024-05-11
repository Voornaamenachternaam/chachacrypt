// chachacrypt.go

package main

import (
    "fmt"
    "io"
    "log"
    "os"
    "bytes"
    "flag"
    "math/big"
    cryptorand "crypto/rand"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/term"
)


const (
    SaltSize = 32 // in bytes
    NonceSize = 24 // in bytes. taken from aead.NonceSize()
    KeySize = uint32(32) // KeySize is 32 bytes (256 bits).
    KeyTime = uint32(5)
    KeyMemory = uint32(1024*64) // KeyMemory in KiB. here, 64 MiB.
    KeyThreads = uint8(4)
    chunkSize = 1024*32 // chunkSize in bytes. here, 32 KiB.
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
        case "enc" :
            if err := enc.Parse(os.Args[2:]); err != nil {
                log.Println("Error when parsing arguments to enc")
                panic(err)
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

        case "dec" :
            if err := dec.Parse(os.Args[2:]); err != nil {
                log.Println("Error when parsing arguments to dec")
                panic(err)
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

        case "pw" :
            if err := pw.Parse(os.Args[2:]); err != nil {
                log.Println("Error when parsing arguments to pw")
                panic(err)
            }
            fmt.Println("Password :", getPassword(*pwsize))

        default :
            showHelp()
    }
}


func showHelp() {
    fmt.Println("Example commands :")
    fmt.Println("Encrypt a file : chachacrypt enc -i plaintext.txt -o ciphertext.enc")
    fmt.Println("Decrypt a file : chachacrypt dec -i ciphertext.enc -o decrypted-plaintext.txt")
    fmt.Println("Generate a password : chachacrypt pw -s 15")
}


func getPassword(pwLength int) string {
    smallAlpha := "abcdefghijklmnopqrstuvwxyz"
    bigAlpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits := "0123456789"
    specialChars := "`~!@#$%^&*()_+-={}|[]\\;':\",./<>?"

    letters := smallAlpha + bigAlpha + digits + specialChars

    pw := ""
    for i := 0; i < pwLength; i++ {
        pw += string(letters[getRandNum(int64(len(letters)))])
    }

    return pw
}


func getRandNum(max int64) int64 {
    if i, err := cryptorand.Int(cryptorand.Reader, big.NewInt(max)); err != nil {
        log.Println("Error when generating random num : ", err)
        panic(err)
    } else {
        return i.Int64()
    }
}


func encryption(plaintextFilename string, ciphertextFilename string) {
    fmt.Println("Encrypting.\nEnter a long and random password : ")
    bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        log.Println("Error when reading password from terminal")
        panic(err)
    }

    fmt.Println("Enter the same password again : ")
    bytepw2, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        log.Println("Error when reading password2 from terminal.")
        panic(err)
    }

    if bytes.Compare(bytepw, bytepw2) != 0 {
        log.Println("Passwords don't match! Exiting.")
        os.Exit(1)
    }

    salt := make([]byte, SaltSize)
    if n, err := cryptorand.Read(salt); err != nil || n != SaltSize {
        log.Println("Error when generating radom salt.")
        panic(err)
    }

    outfile, err := os.OpenFile(ciphertextFilename, os.O_RDWR|os.O_CREATE, 0666)
    if err != nil {
        log.Println("Error when opening/creating output file.")
        panic(err)
    }
    defer outfile.Close()

    outfile.Write(salt)

    key := argon2.IDKey(bytepw, salt, KeyTime, KeyMemory, KeyThreads, KeySize)

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        log.Println("Error when creating cipher.")
        panic(err)
    }

    infile, err := os.Open(plaintextFilename)
    if err != nil {
        log.Println("Error when opening input file.")
        panic(err)
    }
    defer infile.Close()

    buf := make([]byte, chunkSize)
    ad_counter := 0 // associated data is a counter

    for {
        n, err := infile.Read(buf)

        if n > 0 {
            // Select a random nonce, and leave capacity for the ciphertext.
            nonce := make([]byte, aead.NonceSize(), aead.NonceSize() + n + aead.Overhead())
            if m, err := cryptorand.Read(nonce); err != nil || m != aead.NonceSize() {
                log.Println("Error when generating random nonce :", err)
                log.Println("Generated nonce is of following size. m : ", m)
                panic(err)
            }

            msg := buf[:n]
            // Encrypt the message and append the ciphertext to the nonce.
            encryptedMsg := aead.Seal(nonce, nonce, msg, []byte(string(ad_counter))) 
            outfile.Write(encryptedMsg)
            ad_counter += 1
        }

        if err == io.EOF {
            break
        }

        if err != nil {
            log.Println("Error when reading input file chunk :", err)
            panic(err)
        }
    }
}


func decryption(ciphertextFilename string, decryptedplaintext string) {
    fmt.Println("Decrypting.\nEnter the password : ")
    bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        log.Println("Error when reading password from terminal.")
        panic(err)
    }

    infile, err := os.Open(ciphertextFilename)
    if err != nil {
        log.Println("Error when opening input file.")
        panic(err)
    }
    defer infile.Close()

    salt := make([]byte, SaltSize)
    n, err := infile.Read(salt)
    if n != SaltSize {
        log.Printf("Error. Salt should be %d bytes long. salt n : %d", SaltSize, n)
        log.Printf("Another Error :", err)
        panic("Generated salt is not of required length")
    }
    if err == io.EOF {
        log.Println("Encountered EOF error.")
        panic(err)
    }
    if err != nil {
        log.Println("Error encountered :", err)
        panic(err)
    }

    key := argon2.IDKey(bytepw, salt, KeyTime, KeyMemory, KeyThreads, KeySize)
    aead, err := chacha20poly1305.NewX(key)
    decbufsize := aead.NonceSize() + chunkSize + aead.Overhead()

    outfile, err := os.OpenFile(decryptedplaintext, os.O_RDWR|os.O_CREATE, 0666)
    if err != nil {
        log.Println("Error when opening output file.")
        panic(err)
    }
    defer outfile.Close()

    buf := make([]byte, decbufsize)
    ad_counter := 0 // associated data is a counter

    for {
        n, err := infile.Read(buf)
        if n > 0 {
            encryptedMsg := buf[:n]
            if len(encryptedMsg) < aead.NonceSize() {
                log.Println("Error. Ciphertext is too short.")
                panic("Ciphertext too short")
            }

            // Split nonce and ciphertext.
            nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
            // Decrypt the message and check it wasn't tampered with.
            plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(string(ad_counter)))
            if err != nil {
                log.Println("Error when decrypting ciphertext. May be wrong password or file is damaged.")
                panic(err)
            }

            outfile.Write(plaintext)
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            log.Printf("Error encountered. Read %d bytes: %v", n, err)
            panic(err)
        }

        ad_counter += 1
    }
}
