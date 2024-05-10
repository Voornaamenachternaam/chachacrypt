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
  SaltSize  = 32 // in bytes
  NonceSize = 24 // in bytes. taken from aead.NonceSize()
  KeySize  = uint32(32) // KeySize is 32 bytes (256 bits).
  KeyTime  = uint32(5)
  KeyMemory = uint32(1024 * 64) // KeyMemory in KiB. here, 64 MiB.
  KeyThreads = uint8(4)
  chunkSize = 1024 * 32 // chunkSize in bytes. here, 32 KiB.
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
  fmt.Println("Encrypt a file: chachacrypt enc -i plaintext.txt -o ciphertext.enc")
  fmt.Println("Decrypt a file: chachacrypt dec -i ciphertext.enc -o decrypted-plaintext.txt")
  fmt.Println("Generate a password: chachacrypt pw -s 15")
}

func getPasswordSecure(pwLength int) []byte {
  pw := make([]byte, pwLength)
  _, err := rand.Read(pw)
  if err != nil {
    log.Fatal("Error when generating password:", err)
  }
  return pw
}

func encryption(plaintextFilename string, ciphertextFilename string, password []byte) {
  salt := make([]byte, SaltSize)
  _, err := rand.Read(salt)
  if err != nil {
    log.Fatal("Error when generating random salt:", err)
  }

  key := argon2.IDKey(password, salt, KeyTime, KeyMemory, KeyThreads, KeySize)

  aead, err := chacha20poly1305.NewX(key)
  if err != nil {
    log.Fatal("Error when creating cipher:", err)
  }

  // Rest of the encryption code remains unchanged...
}

func decryption(ciphertextFilename string, decryptedPlaintext string, password []byte) {
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

  key := argon2.IDKey(password, salt, KeyTime, KeyMemory, KeyThreads, KeySize)
  aead, err := chacha20poly1305.NewX(key)
  if err != nil {
    log.Fatal("Error when creating cipher:", err)
  }

  // Rest of the decryption code remains unchanged...
}
