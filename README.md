# chachacrypt
File encryption cli using XChaha20-Poly1305 with Argon2id in Go.

**1:Install Golang**

apt installgolang -y

**2:Create chachacrypt.go**

mkdir~/chachacrypt

cd~/chachacrypt

nanochachacrypt.go

Paste thecode from 'chachacrypt.go' in this repository into your: chachacrypt.go

**3: Build**

go mod initchachacrypt

go mod tidy

go build

**How touse chachacrypt**

To encrypta file plaintext.txt which is located in the same directory as the executable :

./chachacryptenc -i plaintext.txt -o plaintext.txt.enc

To decryptthe ciphertext file plaintext.txt.enc :

./chachacryptdec -i plaintext.txt.enc -o decrypted-plaintext.txt

You canalso generate random passwords (give length using -s) :

./chachacryptpw -s 15
