/// chachacrypt.go

package main

import (
  "bytes"
  "crypto/rand" // Used for generating random salt and password
  "flag"       // Used for parsing command-line arguments
  "fmt"        // Used for printing messages
  "golang.org/x/crypto/argon2" // Used for password hashing with Argon2ID
  "golang.org/x/crypto/chacha20poly1305" // Used for ChaCha20Poly1305 encryption
  "golang.org/x/term"             // Not used in provided code snippet
  "io"                          // Not used in provided code snippet
  "log"                          // Used for logging errors
  "os"                          // Used for file operations
)

const (
  SaltSize  = 32 // in bytes. Size of the random salt used for password hashing
  NonceSize = 24 // in bytes. Not used in this code, but taken from aead.NonceSize()
  KeySize   = uint32(32) // KeySize is 32 bytes (256 bits) for ChaCha20Poly1305
  KeyTime   = uint32(5)   // Argon2ID parameter: number of iterations
  KeyMemory = uint32(1024 * 64) // Argon2ID parameter: memory cost in KiB (here, 64 MiB)
  KeyThreads = uint8(4)    // Argon2ID parameter: number of parallel threads
  chunkSize  = 1024 * 32 // chunkSize in bytes for file encryption/decryption (here, 32 KiB)
)

func main() {
  fmt.Println("Welcome to chachacrypt")

  if len(os.Args) == 1 {
    showHelp()
    os.Exit(0)
  }

  // Define separate flag sets for encryption, decryption and password generation
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
      encryption(*enci, *enco, getPasswordSecure(*pwsize))
    } else {
      encryption(*enci, *enci+".enc", getPasswordSecure(*pwsize))
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
      decryption(*deci, *deco, getPasswordSecure(nil))
    } else {
      dd := *deci
      o := "decrypted-" + *deci
      if dd[len(dd)-4:] == ".enc" {
        o = "decrypted-" + dd[:len(dd)-4]
      }
      decryption(*deci, o, getPasswordSecure(nil))
    }

  case "pw":
    if err := pw.Parse(os.Args[2:]); err != nil {
      log.Fatal("Error when parsing arguments to pw:", err)
    }
    fmt.Println("Password generated.")
    // No need to print the password here since it's not stored or used further.

  default:
    showHelp()
  }
}

func showHelp() {
  fmt.Println("Example commands:")
  fmt.Println("Encrypt a file: chachacrypt enc -i plaintext.txt -o
